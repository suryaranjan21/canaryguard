// SPDX-License-Identifier: GPL-2.0-only
/*
 * cg_hooks.c - the guard itself: watches file operations and reacts.
 *
 * HOW WE SEE EVERY FILE OPERATION
 * Whenever any program opens, deletes or renames a file, the kernel first
 * calls a permission-check function. We attach a "kretprobe" to three of
 * them. A kretprobe runs our function when the kernel function is ENTERED
 * (we inspect the request) and again when it RETURNS (we may change the
 * answer to "permission denied").
 *
 *   security_file_open     a file is being opened (read or write)
 *   security_inode_unlink  a file is being deleted
 *   security_inode_rename  a file is being renamed / overwritten
 *
 * WHAT WE LOOK FOR
 *   1. canary touched     a bait file is written / deleted / renamed
 *                         -> block it and kill the process
 *   2. honeytoken read    a fake-secret file is opened for reading
 *                         -> alert only (a harmless tool may do this)
 *   3. speed check        a process changes too many different files inside
 *                         a watched folder within a short time
 *                         -> block it and kill the process
 *
 * Our code runs inside the kernel's file path, so it must be fast and must
 * never sleep. That is why it only touches spinlock-protected memory.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/uidgid.h>

#include "cg_internal.h"

/* ======================================================================== */
/*  Speed check: "how many different files did this process change lately?" */
/* ======================================================================== */

#define CG_TRACK_PROCS  32                      /* processes we follow at once */
#define CG_TRACK_FILES  CG_MAX_SPEED_THRESHOLD  /* files remembered per process */

struct cg_proc {
	pid_t         tgid;
	u64           start_ns;                 /* the stop-watch started here */
	u64           touched_ns;               /* last time we saw it         */
	u32           count;                    /* different files so far      */
	unsigned long ino[CG_TRACK_FILES];      /* which files (inode numbers) */
};

/* Fixed-size table: no memory allocation is allowed in the hook. */
static struct cg_proc cg_procs[CG_TRACK_PROCS];
static DEFINE_SPINLOCK(cg_speed_lock);

static void cg_speed_limits(u32 *files, u32 *window_ms)
{
	*files = clamp_t(u32, READ_ONCE(cg_speed_threshold),
			 CG_MIN_SPEED_THRESHOLD, CG_MAX_SPEED_THRESHOLD);
	*window_ms = clamp_t(u32, READ_ONCE(cg_speed_window_ms),
			     CG_MIN_SPEED_WINDOW_MS, CG_MAX_SPEED_WINDOW_MS);
}

/*
 * Record that process 'tgid' is changing file 'ino'. A stop-watch starts at
 * the process's first change. If it has changed 'threshold' DIFFERENT files
 * before the window runs out, we return true: that is ransomware behaviour.
 */
static bool cg_speed_note(pid_t tgid, unsigned long ino, u32 *count_out)
{
	struct cg_proc *p = NULL, *oldest = &cg_procs[0];
	u32 threshold, window_ms, i, known;
	unsigned long flags;
	bool hit = false, seen = false;
	u64 now = ktime_get_ns();

	cg_speed_limits(&threshold, &window_ms);

	spin_lock_irqsave(&cg_speed_lock, flags);

	for (i = 0; i < CG_TRACK_PROCS; i++) {
		if (cg_procs[i].tgid == tgid) {
			p = &cg_procs[i];
			break;
		}
		if (cg_procs[i].touched_ns < oldest->touched_ns)
			oldest = &cg_procs[i];
	}
	if (!p) {                           /* new process: reuse the oldest slot */
		p = oldest;
		memset(p, 0, sizeof(*p));
		p->tgid = tgid;
		p->start_ns = now;
	}

	if (now - p->start_ns > (u64)window_ms * NSEC_PER_MSEC) {
		p->count = 0;               /* stop-watch ran out: start again */
		p->start_ns = now;
	}
	p->touched_ns = now;

	known = min_t(u32, p->count, CG_TRACK_FILES);
	for (i = 0; i < known; i++) {
		if (p->ino[i] == ino) {
			seen = true;        /* same file again: not a new one */
			break;
		}
	}
	if (!seen) {
		if (p->count < CG_TRACK_FILES)
			p->ino[p->count] = ino;
		p->count++;
	}

	if (p->count >= threshold) {
		*count_out = p->count;
		p->count = 0;               /* start counting afresh */
		p->start_ns = now;
		hit = true;
	}

	spin_unlock_irqrestore(&cg_speed_lock, flags);
	return hit;
}

/* ======================================================================== */
/*  Reacting: build the event, kill the process, tell user space            */
/* ======================================================================== */

/* Processes the guard must leave alone. */
static bool cg_task_ignored(void)
{
	if (current->flags & (PF_KTHREAD | PF_EXITING))
		return true;
	if (is_global_init(current))
		return true;
	if (fatal_signal_pending(current))      /* already on its way out */
		return true;
	return cg_allow_contains(current->comm);
}

/* The name of the file being touched (not the full path: see docs). */
static void cg_copy_name(char *dst, size_t len, struct dentry *dentry)
{
	struct name_snapshot snap;

	if (!dentry)
		return;
	take_dentry_name_snapshot(&snap, dentry);
	strscpy(dst, snap.name.name, len);
	release_dentry_name_snapshot(&snap);
}

static u32 cg_type_for(u32 kind)
{
	return kind == CG_KIND_CANARY ? CG_EV_CANARY : CG_EV_HONEYTOKEN;
}

/*
 * Something suspicious happened. Record it and, when 'destructive' is set
 * and the driver is in kill mode, kill the current process.
 * Returns true when the operation must be DENIED.
 */
static bool cg_raise(u32 type, u32 op, const struct cg_match *m,
		     struct dentry *dentry, u32 count, bool destructive)
{
	u32 threshold, window_ms;
	struct cg_event ev;
	bool kill;

	if (cg_task_ignored())
		return false;

	kill = destructive && READ_ONCE(cg_mode) == CG_MODE_KILL;
	cg_speed_limits(&threshold, &window_ms);

	memset(&ev, 0, sizeof(ev));
	ev.ts_ns     = ktime_get_real_ns();
	ev.type      = type;
	ev.op        = op;
	ev.action    = kill ? CG_ACTION_KILLED : CG_ACTION_ALERT;
	ev.pid       = task_tgid_nr(current);
	ev.uid       = from_kuid(&init_user_ns, current_uid());
	ev.count     = count;
	ev.window_ms = type == CG_EV_SPEED ? window_ms : 0;
	ev.entry_id  = m->id;
	strscpy(ev.comm, current->comm, sizeof(ev.comm));
	strscpy(ev.path, m->path, sizeof(ev.path));
	cg_copy_name(ev.file, sizeof(ev.file), dentry);

	switch (type) {
	case CG_EV_CANARY:     atomic64_inc(&cg_stat.canary_hits);     break;
	case CG_EV_HONEYTOKEN: atomic64_inc(&cg_stat.honeytoken_hits); break;
	case CG_EV_SPEED:      atomic64_inc(&cg_stat.speed_hits);      break;
	}
	cg_table_hit(m->id);

	if (kill) {
		atomic64_inc(&cg_stat.kills);
		/* SIGKILL cannot be caught or ignored; it ends the whole process. */
		send_sig_info(SIGKILL, SEND_SIG_PRIV, current);
	}

	cg_events_push(&ev);
	return kill;
}

/* ======================================================================== */
/*  The three inspections                                                   */
/* ======================================================================== */

/* Behaviour layer: count this change towards the speed limit. */
static bool cg_check_speed(struct inode *inode, struct dentry *dentry, u32 op)
{
	struct cg_match m;
	u32 count;

	if (!READ_ONCE(cg_speed_enabled) || !cg_table_in_watched(dentry, &m))
		return false;
	if (!cg_speed_note(task_tgid_nr(current), inode->i_ino, &count))
		return false;
	return cg_raise(CG_EV_SPEED, op, &m, dentry, count, true);
}

/* Is this inode a decoy? If so, changing it is an attack. */
static bool cg_check_decoy(struct inode *inode, struct dentry *dentry,
			   u32 op, bool *deny)
{
	struct cg_match m;

	if (!inode || !S_ISREG(inode->i_mode) ||
	    !cg_table_match_inode(inode, &m))
		return false;
	*deny = cg_raise(cg_type_for(m.kind), op, &m, dentry, 0, true);
	return true;
}

static bool cg_inspect_open(struct file *file)
{
	struct inode *inode;
	struct cg_match m;
	bool write;

	if (!file || !cg_table_count())     /* nothing registered: do nothing */
		return false;

	inode = file_inode(file);
	if (!S_ISREG(inode->i_mode))
		return false;
	write = file->f_mode & FMODE_WRITE;

	if (cg_table_match_inode(inode, &m)) {
		if (write)
			return cg_raise(cg_type_for(m.kind), CG_OP_WRITE, &m,
					file->f_path.dentry, 0, true);
		if (m.kind == CG_KIND_HONEYTOKEN)       /* snooping: alert only */
			return cg_raise(CG_EV_HONEYTOKEN, CG_OP_READ, &m,
					file->f_path.dentry, 0, false);
		return false;               /* reading a canary is harmless */
	}

	if (write)
		return cg_check_speed(inode, file->f_path.dentry, CG_OP_WRITE);
	return false;
}

static bool cg_inspect_unlink(struct dentry *dentry)
{
	struct inode *inode;
	bool deny = false;

	if (!dentry || !cg_table_count())
		return false;

	inode = d_inode(dentry);
	if (!inode || !S_ISREG(inode->i_mode))
		return false;
	if (cg_check_decoy(inode, dentry, CG_OP_UNLINK, &deny))
		return deny;
	return cg_check_speed(inode, dentry, CG_OP_UNLINK);
}

static bool cg_inspect_rename(struct dentry *old, struct dentry *new)
{
	struct inode *old_inode, *new_inode;
	bool deny = false;

	if (!old || !cg_table_count())
		return false;

	old_inode = d_inode(old);
	new_inode = new ? d_inode(new) : NULL;

	/* renaming a decoy, or overwriting one by renaming over it */
	if (cg_check_decoy(old_inode, old, CG_OP_RENAME, &deny))
		return deny;
	if (cg_check_decoy(new_inode, new, CG_OP_RENAME, &deny))
		return deny;

	if (old_inode && S_ISREG(old_inode->i_mode))
		return cg_check_speed(old_inode, old, CG_OP_RENAME);
	return false;
}

/* ======================================================================== */
/*  kretprobe plumbing                                                      */
/* ======================================================================== */

/* Carried from the "entry" half to the "return" half of one call. */
struct cg_ret {
	bool deny;
};

static int cg_entry_open(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct cg_ret *r = (struct cg_ret *)ri->data;

	/* argument 0 of security_file_open(file) */
	r->deny = cg_inspect_open((struct file *)regs_get_kernel_argument(regs, 0));
	return r->deny ? 0 : 1;         /* 1 = no need to call the return half */
}

static int cg_entry_unlink(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct cg_ret *r = (struct cg_ret *)ri->data;

	/* security_inode_unlink(dir, dentry): the file is argument 1 */
	r->deny = cg_inspect_unlink((struct dentry *)regs_get_kernel_argument(regs, 1));
	return r->deny ? 0 : 1;
}

static int cg_entry_rename(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct cg_ret *r = (struct cg_ret *)ri->data;

	/* security_inode_rename(old_dir, old_dentry, new_dir, new_dentry, flags) */
	r->deny = cg_inspect_rename(
		(struct dentry *)regs_get_kernel_argument(regs, 1),
		(struct dentry *)regs_get_kernel_argument(regs, 3));
	return r->deny ? 0 : 1;
}

/*
 * The kernel function has finished and says "allowed" (0). If we decided to
 * deny, change its answer to "operation not permitted". The caller then
 * aborts the open / delete / rename exactly as it would for any security
 * module saying no.
 */
static int cg_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct cg_ret *r = (struct cg_ret *)ri->data;

	if (r->deny && (long)regs_return_value(regs) == 0)
		regs_set_return_value(regs, -EPERM);
	return 0;
}

#define CG_PROBE(symbol, entry) {				\
	.kp.symbol_name = symbol,				\
	.entry_handler  = entry,				\
	.handler        = cg_ret_handler,			\
	.data_size      = sizeof(struct cg_ret),		\
	.maxactive      = 128,	/* calls in flight at once */	\
}

static struct kretprobe cg_probes[] = {
	CG_PROBE("security_file_open",    cg_entry_open),
	CG_PROBE("security_inode_unlink", cg_entry_unlink),
	CG_PROBE("security_inode_rename", cg_entry_rename),
};

int cg_hooks_init(void)
{
	int i, err;

	for (i = 0; i < ARRAY_SIZE(cg_probes); i++) {
		err = register_kretprobe(&cg_probes[i]);
		if (err < 0) {
			pr_err("cannot hook %s (error %d)\n",
			       cg_probes[i].kp.symbol_name, err);
			goto undo;
		}
	}
	return 0;

undo:
	while (--i >= 0)
		unregister_kretprobe(&cg_probes[i]);
	return err;
}

void cg_hooks_exit(void)
{
	int i;

	/* returns only after no hook of ours is still running */
	for (i = ARRAY_SIZE(cg_probes) - 1; i >= 0; i--)
		unregister_kretprobe(&cg_probes[i]);
}
