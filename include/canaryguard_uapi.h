/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * canaryguard_uapi.h - the contract between the kernel driver and the
 * user-space tools.
 *
 * This single header is included by the C kernel module AND by the C++
 * programs, so both sides always agree on the layout of every structure
 * that crosses the user/kernel boundary (ioctl arguments and events).
 *
 * Rules that keep it safe on both ARM64 and x86-64:
 *   - only fixed-width types (__u32, __u64), never int/long/pointers
 *   - every structure is a multiple of 8 bytes with no hidden padding
 */
#ifndef CANARYGUARD_UAPI_H
#define CANARYGUARD_UAPI_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define CG_DEVICE_NAME     "canaryguard"
#define CG_DEVICE_PATH     "/dev/canaryguard"

#define CG_PATH_MAX        256   /* longest path we store           */
#define CG_NAME_MAX        64    /* longest file name in an event   */
#define CG_COMM_LEN        16    /* length of a process name (comm) */
#define CG_MAX_ENTRIES     64    /* decoys + watched folders        */
#define CG_RING_EVENTS     128   /* capacity of the kernel ring buffer */

/* Defaults for the "speed check" (behaviour layer). */
#define CG_DEFAULT_SPEED_THRESHOLD   10     /* files ...            */
#define CG_DEFAULT_SPEED_WINDOW_MS   2000   /* ... within this time */
#define CG_MIN_SPEED_THRESHOLD       2
#define CG_MAX_SPEED_THRESHOLD       64
#define CG_MIN_SPEED_WINDOW_MS       100
#define CG_MAX_SPEED_WINDOW_MS       60000

/* What a registered path is. */
enum cg_kind {
	CG_KIND_CANARY     = 1,  /* bait file: any change is an attack       */
	CG_KIND_HONEYTOKEN = 2,  /* fake secret: any read is suspicious      */
	CG_KIND_WATCHDIR   = 3,  /* folder under speed-check surveillance    */
};

/* Driver behaviour when an attack is detected. */
enum cg_mode {
	CG_MODE_WARN = 0,        /* only raise an alert                      */
	CG_MODE_KILL = 1,        /* block the operation and kill the process */
};

/* Which trap fired. */
enum cg_event_type {
	CG_EV_CANARY     = 1,
	CG_EV_HONEYTOKEN = 2,
	CG_EV_SPEED      = 3,
};

/* What the offender tried to do. */
enum cg_op {
	CG_OP_WRITE  = 1,        /* open for writing / truncate */
	CG_OP_UNLINK = 2,        /* delete                      */
	CG_OP_RENAME = 3,        /* rename or overwrite         */
	CG_OP_READ   = 4,        /* open for reading            */
};

/* What the driver did about it. */
enum cg_action {
	CG_ACTION_ALERT  = 1,    /* alert only                               */
	CG_ACTION_KILLED = 2,    /* operation blocked and process killed     */
};

/* One security event, as delivered by read() on /dev/canaryguard. */
struct cg_event {
	__u64 seq;                       /* running number, 1, 2, 3 ...        */
	__u64 ts_ns;                     /* wall clock, ns since 1970          */
	__u32 type;                      /* enum cg_event_type                 */
	__u32 op;                        /* enum cg_op                         */
	__u32 action;                    /* enum cg_action                     */
	__u32 pid;                       /* offending process (thread group)   */
	__u32 uid;                       /* user that ran it                   */
	__u32 count;                     /* speed events: files changed        */
	__u32 window_ms;                 /* speed events: the time window      */
	__u32 entry_id;                  /* which registered item matched      */
	char  comm[CG_COMM_LEN];         /* process name                       */
	char  file[CG_NAME_MAX];         /* name of the file that was touched  */
	char  path[CG_PATH_MAX];         /* registered decoy file or folder    */
};

/* One row of the decoy table, as listed by CG_IOC_GET_ENTRY. */
struct cg_entry {
	__u32 id;
	__u32 kind;                      /* enum cg_kind                       */
	__u64 hits;                      /* how often it fired                 */
	char  path[CG_PATH_MAX];
};

struct cg_add_req {                      /* CG_IOC_ADD                         */
	__u32 kind;                      /* in:  enum cg_kind                  */
	__u32 id;                        /* out: id of the new entry           */
	char  path[CG_PATH_MAX];         /* in:  absolute path                 */
};

struct cg_get_entry {                    /* CG_IOC_GET_ENTRY                   */
	__u32 index;                     /* in:  0, 1, 2 ...                   */
	__u32 reserved;
	struct cg_entry entry;           /* out                                */
};

struct cg_stats {                        /* CG_IOC_GET_STATS                   */
	__u64 events;                    /* events queued                      */
	__u64 dropped;                   /* events lost: ring buffer was full  */
	__u64 kills;                     /* processes killed                   */
	__u64 canary_hits;
	__u64 honeytoken_hits;
	__u64 speed_hits;
	__u64 entries;                   /* registered items                   */
	__u64 open_handles;              /* open /dev/canaryguard handles      */
};

struct cg_config {                       /* CG_IOC_GET/SET_CONFIG              */
	__u32 mode;                      /* enum cg_mode                       */
	__u32 speed_enabled;             /* 0 or 1                             */
	__u32 speed_threshold;           /* files                              */
	__u32 speed_window_ms;           /* milliseconds                       */
};

struct cg_allow {                        /* safe list of process names         */
	__u32 index;                     /* used by CG_IOC_ALLOW_GET           */
	__u32 reserved;
	char  comm[CG_COMM_LEN];
};

#define CG_IOC_MAGIC        0xCA

#define CG_IOC_ADD          _IOWR(CG_IOC_MAGIC, 1, struct cg_add_req)
#define CG_IOC_REMOVE       _IOW(CG_IOC_MAGIC, 2, __u32)
#define CG_IOC_CLEAR        _IO(CG_IOC_MAGIC, 3)
#define CG_IOC_GET_ENTRY    _IOWR(CG_IOC_MAGIC, 4, struct cg_get_entry)
#define CG_IOC_GET_STATS    _IOR(CG_IOC_MAGIC, 5, struct cg_stats)
#define CG_IOC_GET_CONFIG   _IOR(CG_IOC_MAGIC, 6, struct cg_config)
#define CG_IOC_SET_CONFIG   _IOW(CG_IOC_MAGIC, 7, struct cg_config)
#define CG_IOC_ALLOW_ADD    _IOW(CG_IOC_MAGIC, 8, struct cg_allow)
#define CG_IOC_ALLOW_DEL    _IOW(CG_IOC_MAGIC, 9, struct cg_allow)
#define CG_IOC_ALLOW_GET    _IOWR(CG_IOC_MAGIC, 10, struct cg_allow)
#define CG_IOC_RESET_STATS  _IO(CG_IOC_MAGIC, 11)

#endif /* CANARYGUARD_UAPI_H */
