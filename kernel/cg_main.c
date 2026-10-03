// SPDX-License-Identifier: GPL-2.0-only
/*
 * CanaryGuard - a kernel-level ransomware and intruder tripwire.
 *
 * cg_main.c: the "front door" of the driver.
 *   - module load / unload
 *   - the character device /dev/canaryguard
 *       read()   delivers security events
 *       poll()   lets a monitor sleep until an event arrives
 *       ioctl()  control commands (register decoys, change settings, stats)
 *   - the sysfs page /sys/class/canaryguard/canaryguard/stats
 *   - module parameters (settings that can be given at load time)
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>

#include "cg_internal.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Suryaranjan Sahoo");
MODULE_DESCRIPTION("CanaryGuard: canary files, honeytokens and a speed check that stop ransomware");
MODULE_VERSION("1.0");

/* ---- module parameters: sudo insmod canaryguard.ko mode=0 ... ----------- */
/* They are also the live settings: see /sys/module/canaryguard/parameters/ */

int cg_mode = CG_MODE_KILL;
module_param_named(mode, cg_mode, int, 0644);
MODULE_PARM_DESC(mode, "1 = block and kill attackers (default), 0 = only raise alerts");

bool cg_speed_enabled = true;
module_param_named(speed_check, cg_speed_enabled, bool, 0644);
MODULE_PARM_DESC(speed_check, "enable the speed check on watched folders (default: 1)");

uint cg_speed_threshold = CG_DEFAULT_SPEED_THRESHOLD;
module_param_named(speed_threshold, cg_speed_threshold, uint, 0644);
MODULE_PARM_DESC(speed_threshold, "different files a process may change within the window (default: 10)");

uint cg_speed_window_ms = CG_DEFAULT_SPEED_WINDOW_MS;
module_param_named(speed_window_ms, cg_speed_window_ms, uint, 0644);
MODULE_PARM_DESC(speed_window_ms, "length of the speed-check window in milliseconds (default: 2000)");

/* ---- statistics --------------------------------------------------------- */

struct cg_counters cg_stat;
atomic_t cg_open_handles = ATOMIC_INIT(0);

static void cg_fill_stats(struct cg_stats *s)
{
	memset(s, 0, sizeof(*s));
	s->events          = atomic64_read(&cg_stat.events);
	s->dropped         = atomic64_read(&cg_stat.dropped);
	s->kills           = atomic64_read(&cg_stat.kills);
	s->canary_hits     = atomic64_read(&cg_stat.canary_hits);
	s->honeytoken_hits = atomic64_read(&cg_stat.honeytoken_hits);
	s->speed_hits      = atomic64_read(&cg_stat.speed_hits);
	s->entries         = cg_table_count();
	s->open_handles    = atomic_read(&cg_open_handles);
}

/* ---- the character device ---------------------------------------------- */

static dev_t cg_devt;
static struct cdev cg_cdev;
static struct class *cg_class;
static struct device *cg_device;

static int cg_open(struct inode *inode, struct file *filp)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	atomic_inc(&cg_open_handles);
	return nonseekable_open(inode, filp);
}

static int cg_release(struct inode *inode, struct file *filp)
{
	atomic_dec(&cg_open_handles);
	return 0;
}

static ssize_t cg_read(struct file *filp, char __user *buf, size_t count,
		       loff_t *ppos)
{
	return cg_events_read(buf, count, filp->f_flags & O_NONBLOCK);
}

static __poll_t cg_poll(struct file *filp, struct poll_table_struct *wait)
{
	return cg_events_poll(filp, wait);
}

static long cg_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	switch (cmd) {
	case CG_IOC_ADD: {
		struct cg_add_req req;

		if (copy_from_user(&req, argp, sizeof(req)))
			return -EFAULT;
		req.path[sizeof(req.path) - 1] = '\0';
		err = cg_table_add(req.kind, req.path, &req.id);
		if (err)
			return err;
		return copy_to_user(argp, &req, sizeof(req)) ? -EFAULT : 0;
	}
	case CG_IOC_REMOVE: {
		u32 id;

		if (get_user(id, (u32 __user *)argp))
			return -EFAULT;
		return cg_table_remove(id);
	}
	case CG_IOC_CLEAR:
		cg_table_clear();
		return 0;
	case CG_IOC_RESET_STATS:
		atomic64_set(&cg_stat.events, 0);
		atomic64_set(&cg_stat.dropped, 0);
		atomic64_set(&cg_stat.kills, 0);
		atomic64_set(&cg_stat.canary_hits, 0);
		atomic64_set(&cg_stat.honeytoken_hits, 0);
		atomic64_set(&cg_stat.speed_hits, 0);
		return 0;
	case CG_IOC_GET_ENTRY: {
		struct cg_get_entry ge;

		if (copy_from_user(&ge, argp, sizeof(ge)))
			return -EFAULT;
		err = cg_table_get(ge.index, &ge.entry);
		if (err)
			return err;
		return copy_to_user(argp, &ge, sizeof(ge)) ? -EFAULT : 0;
	}
	case CG_IOC_GET_STATS: {
		struct cg_stats st;

		cg_fill_stats(&st);
		return copy_to_user(argp, &st, sizeof(st)) ? -EFAULT : 0;
	}
	case CG_IOC_GET_CONFIG: {
		struct cg_config cfg = {
			.mode            = READ_ONCE(cg_mode),
			.speed_enabled   = READ_ONCE(cg_speed_enabled),
			.speed_threshold = READ_ONCE(cg_speed_threshold),
			.speed_window_ms = READ_ONCE(cg_speed_window_ms),
		};

		return copy_to_user(argp, &cfg, sizeof(cfg)) ? -EFAULT : 0;
	}
	case CG_IOC_SET_CONFIG: {
		struct cg_config cfg;

		if (copy_from_user(&cfg, argp, sizeof(cfg)))
			return -EFAULT;
		if (cfg.mode > CG_MODE_KILL || cfg.speed_enabled > 1 ||
		    cfg.speed_threshold < CG_MIN_SPEED_THRESHOLD ||
		    cfg.speed_threshold > CG_MAX_SPEED_THRESHOLD ||
		    cfg.speed_window_ms < CG_MIN_SPEED_WINDOW_MS ||
		    cfg.speed_window_ms > CG_MAX_SPEED_WINDOW_MS)
			return -EINVAL;
		WRITE_ONCE(cg_mode, cfg.mode);
		WRITE_ONCE(cg_speed_enabled, cfg.speed_enabled);
		WRITE_ONCE(cg_speed_threshold, cfg.speed_threshold);
		WRITE_ONCE(cg_speed_window_ms, cfg.speed_window_ms);
		pr_info("settings changed: mode=%s speed=%s %u files / %u ms\n",
			cfg.mode == CG_MODE_KILL ? "kill" : "warn",
			cfg.speed_enabled ? "on" : "off",
			cfg.speed_threshold, cfg.speed_window_ms);
		return 0;
	}
	case CG_IOC_ALLOW_ADD:
	case CG_IOC_ALLOW_DEL: {
		struct cg_allow al;

		if (copy_from_user(&al, argp, sizeof(al)))
			return -EFAULT;
		al.comm[sizeof(al.comm) - 1] = '\0';
		return cmd == CG_IOC_ALLOW_ADD ? cg_allow_add(al.comm)
					       : cg_allow_del(al.comm);
	}
	case CG_IOC_ALLOW_GET: {
		struct cg_allow al;

		if (copy_from_user(&al, argp, sizeof(al)))
			return -EFAULT;
		err = cg_allow_get(al.index, al.comm);
		if (err)
			return err;
		return copy_to_user(argp, &al, sizeof(al)) ? -EFAULT : 0;
	}
	default:
		return -ENOTTY;
	}
}

static const struct file_operations cg_fops = {
	.owner          = THIS_MODULE,
	.open           = cg_open,
	.release        = cg_release,
	.read           = cg_read,
	.poll           = cg_poll,
	.unlocked_ioctl = cg_ioctl,
	.llseek         = no_llseek,
};

/* ---- sysfs: cat /sys/class/canaryguard/canaryguard/stats ---------------- */

static ssize_t stats_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct cg_stats s;

	cg_fill_stats(&s);
	return sysfs_emit(buf,
		"events %llu\ndropped %llu\nkills %llu\n"
		"canary_hits %llu\nhoneytoken_hits %llu\nspeed_hits %llu\n"
		"entries %llu\nmode %s\n",
		s.events, s.dropped, s.kills, s.canary_hits,
		s.honeytoken_hits, s.speed_hits, s.entries,
		READ_ONCE(cg_mode) == CG_MODE_KILL ? "kill" : "warn");
}
static DEVICE_ATTR_RO(stats);

static struct attribute *cg_attrs[] = {
	&dev_attr_stats.attr,
	NULL,
};
ATTRIBUTE_GROUPS(cg);

/* make /dev/canaryguard readable by root only */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
static char *cg_devnode(const struct device *dev, umode_t *mode)
#else
static char *cg_devnode(struct device *dev, umode_t *mode)
#endif
{
	if (mode)
		*mode = 0600;
	return NULL;
}

/* ---- load / unload ------------------------------------------------------ */

static int __init cg_init(void)
{
	int err;

	/* the user/kernel contract must have the same size on every CPU type */
	BUILD_BUG_ON(sizeof(struct cg_event) != 384);
	BUILD_BUG_ON(sizeof(struct cg_entry) != 272);
	BUILD_BUG_ON(sizeof(struct cg_add_req) != 264);
	BUILD_BUG_ON(sizeof(struct cg_get_entry) != 280);
	BUILD_BUG_ON(sizeof(struct cg_stats) != 64);
	BUILD_BUG_ON(sizeof(struct cg_config) != 16);
	BUILD_BUG_ON(sizeof(struct cg_allow) != 24);

	err = cg_events_init();
	if (err)
		return err;
	cg_allow_defaults();

	err = alloc_chrdev_region(&cg_devt, 0, 1, CG_DEVICE_NAME);
	if (err)
		goto err_events;

	cdev_init(&cg_cdev, &cg_fops);
	cg_cdev.owner = THIS_MODULE;
	err = cdev_add(&cg_cdev, cg_devt, 1);
	if (err)
		goto err_region;

	cg_class = cg_class_create(CG_DEVICE_NAME);
	if (IS_ERR(cg_class)) {
		err = PTR_ERR(cg_class);
		goto err_cdev;
	}
	cg_class->devnode = cg_devnode;

	cg_device = device_create_with_groups(cg_class, NULL, cg_devt, NULL,
					      cg_groups, CG_DEVICE_NAME);
	if (IS_ERR(cg_device)) {
		err = PTR_ERR(cg_device);
		goto err_class;
	}

	/* hooks go live last: everything they use must already exist */
	err = cg_hooks_init();
	if (err)
		goto err_device;

	pr_info("loaded: mode=%s, speed check %s (%u files / %u ms), device %s\n",
		cg_mode == CG_MODE_KILL ? "kill" : "warn",
		cg_speed_enabled ? "on" : "off",
		cg_speed_threshold, cg_speed_window_ms, CG_DEVICE_PATH);
	return 0;

err_device:
	device_destroy(cg_class, cg_devt);
err_class:
	class_destroy(cg_class);
err_cdev:
	cdev_del(&cg_cdev);
err_region:
	unregister_chrdev_region(cg_devt, 1);
err_events:
	cg_events_exit();
	return err;
}

static void __exit cg_exit(void)
{
	cg_hooks_exit();                    /* first: stop watching */
	device_destroy(cg_class, cg_devt);
	class_destroy(cg_class);
	cdev_del(&cg_cdev);
	unregister_chrdev_region(cg_devt, 1);
	cg_table_clear();                   /* release the pinned files */
	cg_events_exit();
	pr_info("unloaded\n");
}

module_init(cg_init);
module_exit(cg_exit);
