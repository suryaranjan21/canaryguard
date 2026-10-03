// SPDX-License-Identifier: GPL-2.0-only
/*
 * cg_events.c - how alerts travel from the kernel to user space.
 *
 *   detection hook ──> cg_events_push() ──> ring buffer (kfifo) ──> read()
 *                                      └──> log queue ──> workqueue ──> dmesg
 *
 * The hooks run in a very restricted context (they cannot sleep and should
 * be fast), so they only do the cheap part ("top half"): copy the event into
 * a fixed-size ring buffer and wake up any reader. The slow part, printing
 * to the kernel log, is pushed to a workqueue ("bottom half").
 *
 * If the ring buffer is full the NEW event is dropped and counted, so the
 * monitor can report "N events lost" instead of silently missing them.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kfifo.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "cg_internal.h"

#define CG_LOG_QUEUE 32            /* events waiting to be printed (power of 2) */

static DECLARE_KFIFO_PTR(cg_ring, struct cg_event);   /* towards user space */
static DECLARE_KFIFO_PTR(cg_logq, struct cg_event);   /* towards dmesg      */
static DEFINE_SPINLOCK(cg_prod_lock);                 /* one producer at a time */
static DEFINE_MUTEX(cg_read_lock);                    /* one reader at a time   */
static DECLARE_WAIT_QUEUE_HEAD(cg_waitq);
static struct work_struct cg_log_work;
static u64 cg_seq;

/* ---- bottom half: print to the kernel log ------------------------------ */

static void cg_log_one(const struct cg_event *ev)
{
	const char *act = ev->action == CG_ACTION_KILLED ? "KILLED" : "ALERT";
	const char *op;

	switch (ev->op) {
	case CG_OP_WRITE:  op = "write";  break;
	case CG_OP_UNLINK: op = "delete"; break;
	case CG_OP_RENAME: op = "rename"; break;
	default:           op = "read";   break;
	}

	switch (ev->type) {
	case CG_EV_SPEED:
		pr_warn("[%s] speed check: %s[%u] uid=%u changed %u files in %u ms in %s (last: %s)\n",
			act, ev->comm, ev->pid, ev->uid, ev->count,
			ev->window_ms, ev->path, ev->file);
		break;
	case CG_EV_HONEYTOKEN:
		pr_warn("[%s] honeytoken %s: %s[%u] uid=%u -> %s\n",
			act, op, ev->comm, ev->pid, ev->uid, ev->path);
		break;
	default:
		pr_warn("[%s] canary %s: %s[%u] uid=%u -> %s\n",
			act, op, ev->comm, ev->pid, ev->uid, ev->path);
		break;
	}
}

static void cg_log_worker(struct work_struct *work)
{
	struct cg_event ev;

	while (kfifo_out(&cg_logq, &ev, 1) == 1)
		cg_log_one(&ev);
}

/* ---- top half: called by the detection hooks (atomic context) ---------- */

void cg_events_push(struct cg_event *ev)
{
	unsigned long flags;
	unsigned int queued;

	spin_lock_irqsave(&cg_prod_lock, flags);
	ev->seq = ++cg_seq;
	queued = kfifo_in(&cg_ring, ev, 1);    /* 0 when the ring is full */
	kfifo_in(&cg_logq, ev, 1);             /* dmesg still gets it     */
	spin_unlock_irqrestore(&cg_prod_lock, flags);

	atomic64_inc(&cg_stat.events);
	if (queued)
		wake_up_interruptible(&cg_waitq);
	else
		atomic64_inc(&cg_stat.dropped);

	schedule_work(&cg_log_work);
}

/* ---- the read() and poll() side (process context) ---------------------- */

ssize_t cg_events_read(char __user *buf, size_t count, bool nonblock)
{
	unsigned int copied = 0;
	int ret;

	if (count < sizeof(struct cg_event))
		return -EINVAL;

	if (mutex_lock_interruptible(&cg_read_lock))
		return -ERESTARTSYS;

	while (kfifo_is_empty(&cg_ring)) {
		mutex_unlock(&cg_read_lock);
		if (nonblock)
			return -EAGAIN;
		if (wait_event_interruptible(cg_waitq, !kfifo_is_empty(&cg_ring)))
			return -ERESTARTSYS;
		if (mutex_lock_interruptible(&cg_read_lock))
			return -ERESTARTSYS;
	}

	/* hands out whole events only; 'copied' is in bytes */
	ret = kfifo_to_user(&cg_ring, buf, count, &copied);
	mutex_unlock(&cg_read_lock);

	return ret ? ret : copied;
}

__poll_t cg_events_poll(struct file *file, struct poll_table_struct *wait)
{
	__poll_t mask = 0;

	poll_wait(file, &cg_waitq, wait);
	if (!kfifo_is_empty(&cg_ring))
		mask |= EPOLLIN | EPOLLRDNORM;
	return mask;
}

/* ---- setup / teardown -------------------------------------------------- */

int cg_events_init(void)
{
	int err;

	INIT_WORK(&cg_log_work, cg_log_worker);

	err = kfifo_alloc(&cg_ring, CG_RING_EVENTS, GFP_KERNEL);
	if (err)
		return err;
	err = kfifo_alloc(&cg_logq, CG_LOG_QUEUE, GFP_KERNEL);
	if (err) {
		kfifo_free(&cg_ring);
		return err;
	}
	return 0;
}

void cg_events_exit(void)
{
	flush_work(&cg_log_work);       /* let pending lines reach dmesg */
	kfifo_free(&cg_logq);
	kfifo_free(&cg_ring);
}
