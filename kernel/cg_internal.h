/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * cg_internal.h - private declarations shared by the files of the driver.
 *
 *   cg_main.c    module init/exit, /dev/canaryguard, ioctl, sysfs
 *   cg_table.c   the list of decoys / watched folders / safe list
 *   cg_hooks.c   the detection logic (kretprobes + speed check + kill)
 *   cg_events.c  the ring buffer that carries alerts to user space
 */
#ifndef CG_INTERNAL_H
#define CG_INTERNAL_H

#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/version.h>

#include <canaryguard_uapi.h>

/* ---- live configuration: these are also the module parameters ---------- */
extern int cg_mode;              /* enum cg_mode                            */
extern bool cg_speed_enabled;
extern uint cg_speed_threshold;
extern uint cg_speed_window_ms;

/* ---- statistics (atomic: updated from hooks running on any CPU) -------- */
struct cg_counters {
	atomic64_t events;
	atomic64_t dropped;
	atomic64_t kills;
	atomic64_t canary_hits;
	atomic64_t honeytoken_hits;
	atomic64_t speed_hits;
};
extern struct cg_counters cg_stat;
extern atomic_t cg_open_handles;

/* ---- cg_table.c -------------------------------------------------------- */
struct cg_match {                /* result of a table lookup                */
	u32  id;
	u32  kind;
	char path[CG_PATH_MAX];
};

unsigned int cg_table_count(void);
int  cg_table_add(u32 kind, const char *path, u32 *id_out);
int  cg_table_remove(u32 id);
void cg_table_clear(void);
int  cg_table_get(u32 index, struct cg_entry *out);
void cg_table_hit(u32 id);
bool cg_table_match_inode(struct inode *inode, struct cg_match *m);
bool cg_table_in_watched(struct dentry *dentry, struct cg_match *m);

void cg_allow_defaults(void);
int  cg_allow_add(const char *comm);
int  cg_allow_del(const char *comm);
int  cg_allow_get(u32 index, char *comm_out);
bool cg_allow_contains(const char *comm);

/* ---- cg_events.c ------------------------------------------------------- */
int  cg_events_init(void);
void cg_events_exit(void);
void cg_events_push(struct cg_event *ev);    /* safe in atomic context */
ssize_t cg_events_read(char __user *buf, size_t count, bool nonblock);
__poll_t cg_events_poll(struct file *file, struct poll_table_struct *wait);

/* ---- cg_hooks.c -------------------------------------------------------- */
int  cg_hooks_init(void);
void cg_hooks_exit(void);

/* ---- small compatibility helper --------------------------------------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
#define cg_class_create(name)   class_create(name)
#else
#define cg_class_create(name)   class_create(THIS_MODULE, name)
#endif

#endif /* CG_INTERNAL_H */
