// SPDX-License-Identifier: GPL-2.0-only
/*
 * cg_table.c - the driver's memory of what to protect.
 *
 * Three kinds of entries live in one list:
 *   canary     a bait file         (compared by inode)
 *   honeytoken a fake-secret file  (compared by inode)
 *   watchdir   a folder under speed-check surveillance (compared by ancestry)
 *
 * Locking: the detection hooks can run on every CPU at the same time and are
 * not allowed to sleep, so the list is protected by a SPINLOCK. Anything that
 * may sleep (path_put, kfree of a path) is done after the lock is released.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "cg_internal.h"

struct cg_entry_k {
	struct list_head node;
	u32              id;
	u32              kind;
	struct path      where;   /* keeps the dentry (and so the inode) alive */
	struct inode    *inode;
	atomic64_t       hits;
	char             name[CG_PATH_MAX];
};

static LIST_HEAD(cg_entries);
static DEFINE_SPINLOCK(cg_lock);
static atomic_t cg_count = ATOMIC_INIT(0);
static u32 cg_next_id = 1;

/* Process names that are never blocked or killed (see docs: limitations). */
#define CG_MAX_ALLOW 8
static char cg_allow[CG_MAX_ALLOW][CG_COMM_LEN];

/*
 * Folders that must never be watched: the speed check could otherwise kill
 * the package manager or the system itself.
 */
static const char * const cg_forbidden_dirs[] = {
	"/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc",
	"/run", "/sbin", "/sys", "/tmp", "/usr", "/var",
};

static bool cg_is_forbidden_dir(const struct path *p)
{
	struct path sys;
	bool same;
	int i;

	for (i = 0; i < ARRAY_SIZE(cg_forbidden_dirs); i++) {
		if (kern_path(cg_forbidden_dirs[i], LOOKUP_FOLLOW, &sys))
			continue;
		same = (sys.dentry == p->dentry);
		path_put(&sys);
		if (same)
			return true;
	}
	return false;
}

/* Cheap check used on the hot path: is anything registered at all? */
unsigned int cg_table_count(void)
{
	return atomic_read(&cg_count);
}

int cg_table_add(u32 kind, const char *name, u32 *id_out)
{
	struct cg_entry_k *e, *dup;
	struct inode *inode;
	unsigned long flags;
	int err;

	if (kind != CG_KIND_CANARY && kind != CG_KIND_HONEYTOKEN &&
	    kind != CG_KIND_WATCHDIR)
		return -EINVAL;
	if (!name[0])
		return -EINVAL;
	if (atomic_read(&cg_count) >= CG_MAX_ENTRIES)
		return -ENOSPC;

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;

	/* Resolve the path now; the stored struct path pins the file. */
	err = kern_path(name, LOOKUP_FOLLOW, &e->where);
	if (err)
		goto out_free;

	inode = d_inode(e->where.dentry);
	if (kind == CG_KIND_WATCHDIR) {
		if (!S_ISDIR(inode->i_mode)) {
			err = -ENOTDIR;
			goto out_put;
		}
		if (cg_is_forbidden_dir(&e->where)) {
			pr_warn("refusing to watch a system directory: %s\n", name);
			err = -EPERM;
			goto out_put;
		}
	} else if (!S_ISREG(inode->i_mode)) {
		err = -EINVAL;
		goto out_put;
	}

	e->kind  = kind;
	e->inode = inode;
	atomic64_set(&e->hits, 0);
	strscpy(e->name, name, sizeof(e->name));

	spin_lock_irqsave(&cg_lock, flags);
	list_for_each_entry(dup, &cg_entries, node) {
		/* the same file may not be registered twice, in any role */
		bool both_files = dup->kind != CG_KIND_WATCHDIR &&
				  kind != CG_KIND_WATCHDIR;

		if (dup->inode == inode &&
		    (dup->kind == kind || both_files)) {
			err = -EEXIST;
			break;
		}
	}
	if (!err) {
		e->id = cg_next_id++;
		list_add_tail(&e->node, &cg_entries);
		atomic_inc(&cg_count);
	}
	spin_unlock_irqrestore(&cg_lock, flags);
	if (err)
		goto out_put;

	*id_out = e->id;
	return 0;

out_put:
	path_put(&e->where);
out_free:
	kfree(e);
	return err;
}

int cg_table_remove(u32 id)
{
	struct cg_entry_k *e, *found = NULL;
	unsigned long flags;

	spin_lock_irqsave(&cg_lock, flags);
	list_for_each_entry(e, &cg_entries, node) {
		if (e->id == id) {
			found = e;
			list_del(&e->node);
			atomic_dec(&cg_count);
			break;
		}
	}
	spin_unlock_irqrestore(&cg_lock, flags);

	if (!found)
		return -ENOENT;
	path_put(&found->where);   /* may sleep: only after the unlock */
	kfree(found);
	return 0;
}

void cg_table_clear(void)
{
	struct cg_entry_k *e, *tmp;
	unsigned long flags;
	LIST_HEAD(dead);

	spin_lock_irqsave(&cg_lock, flags);
	list_splice_init(&cg_entries, &dead);
	atomic_set(&cg_count, 0);
	cg_next_id = 1;                 /* a fresh start: numbering begins at 1 */
	spin_unlock_irqrestore(&cg_lock, flags);

	list_for_each_entry_safe(e, tmp, &dead, node) {
		path_put(&e->where);
		kfree(e);
	}
}

int cg_table_get(u32 index, struct cg_entry *out)
{
	struct cg_entry_k *e;
	unsigned long flags;
	int err = -ENOENT;

	spin_lock_irqsave(&cg_lock, flags);
	list_for_each_entry(e, &cg_entries, node) {
		if (index-- == 0) {
			out->id   = e->id;
			out->kind = e->kind;
			out->hits = atomic64_read(&e->hits);
			strscpy(out->path, e->name, sizeof(out->path));
			err = 0;
			break;
		}
	}
	spin_unlock_irqrestore(&cg_lock, flags);
	return err;
}

/* Count one "this decoy fired" for the list shown by canaryctl. */
void cg_table_hit(u32 id)
{
	struct cg_entry_k *e;
	unsigned long flags;

	spin_lock_irqsave(&cg_lock, flags);
	list_for_each_entry(e, &cg_entries, node) {
		if (e->id == id) {
			atomic64_inc(&e->hits);
			break;
		}
	}
	spin_unlock_irqrestore(&cg_lock, flags);
}

/* Is this inode one of our canaries or honeytokens? */
bool cg_table_match_inode(struct inode *inode, struct cg_match *m)
{
	struct cg_entry_k *e;
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(&cg_lock, flags);
	list_for_each_entry(e, &cg_entries, node) {
		if (e->kind == CG_KIND_WATCHDIR || e->inode != inode)
			continue;
		m->id   = e->id;
		m->kind = e->kind;
		strscpy(m->path, e->name, sizeof(m->path));
		found = true;
		break;
	}
	spin_unlock_irqrestore(&cg_lock, flags);
	return found;
}

/* Does this dentry live inside a watched folder? */
bool cg_table_in_watched(struct dentry *dentry, struct cg_match *m)
{
	struct cg_entry_k *e;
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(&cg_lock, flags);
	list_for_each_entry(e, &cg_entries, node) {
		if (e->kind != CG_KIND_WATCHDIR)
			continue;
		if (is_subdir(dentry, e->where.dentry)) {
			m->id   = e->id;
			m->kind = e->kind;
			strscpy(m->path, e->name, sizeof(m->path));
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&cg_lock, flags);
	return found;
}

/* ---- safe list of process names --------------------------------------- */

int cg_allow_add(const char *comm)
{
	unsigned long flags;
	int i, free_slot = -1, err = 0;

	if (!comm[0])
		return -EINVAL;

	spin_lock_irqsave(&cg_lock, flags);
	for (i = 0; i < CG_MAX_ALLOW; i++) {
		if (!cg_allow[i][0]) {
			if (free_slot < 0)
				free_slot = i;
		} else if (!strncmp(cg_allow[i], comm, CG_COMM_LEN - 1)) {
			err = -EEXIST;
			break;
		}
	}
	if (!err) {
		if (free_slot < 0)
			err = -ENOSPC;
		else
			strscpy(cg_allow[free_slot], comm, CG_COMM_LEN);
	}
	spin_unlock_irqrestore(&cg_lock, flags);
	return err;
}

int cg_allow_del(const char *comm)
{
	unsigned long flags;
	int i, err = -ENOENT;

	spin_lock_irqsave(&cg_lock, flags);
	for (i = 0; i < CG_MAX_ALLOW; i++) {
		if (cg_allow[i][0] &&
		    !strncmp(cg_allow[i], comm, CG_COMM_LEN - 1)) {
			cg_allow[i][0] = '\0';
			err = 0;
			break;
		}
	}
	spin_unlock_irqrestore(&cg_lock, flags);
	return err;
}

int cg_allow_get(u32 index, char *comm_out)
{
	unsigned long flags;
	int i, err = -ENOENT;

	spin_lock_irqsave(&cg_lock, flags);
	for (i = 0; i < CG_MAX_ALLOW; i++) {
		if (!cg_allow[i][0])
			continue;
		if (index-- == 0) {
			strscpy(comm_out, cg_allow[i], CG_COMM_LEN);
			err = 0;
			break;
		}
	}
	spin_unlock_irqrestore(&cg_lock, flags);
	return err;
}

bool cg_allow_contains(const char *comm)
{
	unsigned long flags;
	bool found = false;
	int i;

	spin_lock_irqsave(&cg_lock, flags);
	for (i = 0; i < CG_MAX_ALLOW; i++) {
		if (cg_allow[i][0] &&
		    !strncmp(cg_allow[i], comm, CG_COMM_LEN - 1)) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&cg_lock, flags);
	return found;
}

/* Our own tools must never be killed by their own guard. */
void cg_allow_defaults(void)
{
	cg_allow_add("canaryctl");
	cg_allow_add("canaryd");
	cg_allow_add("cgdemo");
}
