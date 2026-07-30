// SPDX-License-Identifier: GPL-2.0
// shadowmask_sus.c — ShadowMask SUSFS LKM (main entry point)
//
// Loadable kernel module that implements SUSFS hiding features without
// kernel source patching. Compatible with the ksu_susfs userspace tool.
//
// Requirements (all present on the target kernel):
//   CONFIG_MODULES=y, CONFIG_MODULE_SIG not set,
//   CONFIG_KALLSYMS_ALL=y, CONFIG_FTRACE=y
//
// Features:
//   - sus_path  : hide paths from app processes
//   - sus_mount : hide root mount entries from /proc/pid/mountinfo
//   - sus_kstat : spoof file stat() results
//   - sus_map   : hide entries from /proc/pid/maps
//   - set_uname : spoof kernel uname strings
//   - open_redirect : redirect file opens to alternate paths

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include "shadowmask_sus.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ShadowMask Project");
MODULE_DESCRIPTION("SUSFS userspace-compatible hiding layer (LKM)");
MODULE_VERSION("2.2.0-lkm");

/* ── Global state (shared internally with syscall_hook.c and proc_filter.c) ── */
LIST_HEAD(sm_sus_paths);
LIST_HEAD(sm_sus_kstats);
LIST_HEAD(sm_sus_maps);
LIST_HEAD(sm_open_redirects);
DEFINE_SPINLOCK(sm_sus_lock);
bool sm_hide_sus_mnts = false;
bool sm_log_enabled   = false;

/* ── Cleanup helpers ── */
static void free_list_sus_path(void)
{
    struct sus_path_node *node, *tmp;
    spin_lock(&sm_sus_lock);
    list_for_each_entry_safe(node, tmp, &sm_sus_paths, list) {
        list_del(&node->list);
        kfree(node);
    }
    spin_unlock(&sm_sus_lock);
}

static void free_list_sus_kstat(void)
{
    struct sus_kstat_node *node, *tmp;
    spin_lock(&sm_sus_lock);
    list_for_each_entry_safe(node, tmp, &sm_sus_kstats, list) {
        list_del(&node->list);
        kfree(node);
    }
    spin_unlock(&sm_sus_lock);
}

static void free_list_sus_map(void)
{
    struct sus_map_node *node, *tmp;
    spin_lock(&sm_sus_lock);
    list_for_each_entry_safe(node, tmp, &sm_sus_maps, list) {
        list_del(&node->list);
        kfree(node);
    }
    spin_unlock(&sm_sus_lock);
}

static void free_list_open_redirect(void)
{
    struct sus_open_redirect_node *node, *tmp;
    spin_lock(&sm_sus_lock);
    list_for_each_entry_safe(node, tmp, &sm_open_redirects, list) {
        list_del(&node->list);
        kfree(node);
    }
    spin_unlock(&sm_sus_lock);
}

/* ── Module init ── */
static int __init shadowmask_sus_init(void)
{
    int ret;

    sm_info("loading (version %s)", SUSFS_VERSION);

    /* Install syscall hook to receive ksu_susfs commands */
    ret = sm_syscall_hook_init();
    if (ret) {
        sm_err("syscall hook failed (%d) — module aborted", ret);
        return ret;
    }

    /* Hook procfs seq_file operations for maps/mountinfo filtering */
    ret = sm_proc_hook_init();
    if (ret) {
        sm_err("proc hook failed (%d) — continuing without proc filter", ret);
        /* Non-fatal: syscall hook still works for command reception */
    }

    sm_info("ready. susfs ABI=%s", SUSFS_VERSION);
    return 0;
}

/* ── Module exit ── */
static void __exit shadowmask_sus_exit(void)
{
    sm_info("unloading");

    sm_proc_hook_exit();
    sm_syscall_hook_exit();

    free_list_sus_path();
    free_list_sus_kstat();
    free_list_sus_map();
    free_list_open_redirect();

    sm_info("unloaded");
}

module_init(shadowmask_sus_init);
module_exit(shadowmask_sus_exit);
