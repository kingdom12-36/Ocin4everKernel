// SPDX-License-Identifier: GPL-2.0
// syscall_hook.c — intercept SYS_reboot to receive SUSFS commands
//
// Strategy: find sys_call_table via kallsyms, make the page writable,
// swap entry[__NR_reboot] with our handler, restore protection.
// Compatible with arm64 4.14 (CONFIG_STRICT_MODULE_RWX=y).

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/reboot.h>
#include <linux/utsname.h>
#include <linux/rwsem.h>
#include <uapi/linux/utsname.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include "shadowmask_sus.h"

/* ── Symbol resolution ── */
typedef int (*set_mem_rw_fn_t)(unsigned long addr, int numpages);
typedef int (*set_mem_ro_fn_t)(unsigned long addr, int numpages);
static set_mem_rw_fn_t _set_memory_rw;
static set_mem_ro_fn_t _set_memory_ro;

/* Original reboot syscall pointer */
typedef asmlinkage long (*orig_reboot_t)(int magic1, int magic2,
                                          unsigned int cmd, void __user *arg);
static orig_reboot_t orig_sys_reboot;
static unsigned long *syscall_table;

/* ── Memory protection helpers ── */
static void make_rw(unsigned long addr)
{
    if (_set_memory_rw)
        _set_memory_rw(addr & PAGE_MASK, 1);
}

static void make_ro(unsigned long addr)
{
    if (_set_memory_ro)
        _set_memory_ro(addr & PAGE_MASK, 1);
}

/* ── SUSFS command handlers ── */

static long handle_add_sus_path(void __user *uarg, bool loop)
{
    struct st_susfs_sus_path info;
    struct sus_path_node *node;

    if (copy_from_user(&info, uarg, sizeof(info)))
        return -EFAULT;

    node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node) return -ENOMEM;

    strlcpy(node->pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME);
    node->loop = loop;

    spin_lock(&sm_sus_lock);
    list_add_tail(&node->list, &sm_sus_paths);
    spin_unlock(&sm_sus_lock);

    info.err = 0;
    if (copy_to_user(uarg, &info, sizeof(info)))
        return -EFAULT;

    sm_dbg("add_sus_path: %s (loop=%d)", node->pathname, loop);
    return 0;
}

static long handle_hide_sus_mnts(void __user *uarg)
{
    struct st_susfs_sus_mount info;

    if (copy_from_user(&info, uarg, sizeof(info)))
        return -EFAULT;

    spin_lock(&sm_sus_lock);
    sm_hide_sus_mnts = !!info.enabled;
    spin_unlock(&sm_sus_lock);

    info.err = 0;
    if (copy_to_user(uarg, &info, sizeof(info)))
        return -EFAULT;

    sm_dbg("hide_sus_mnts: %d", sm_hide_sus_mnts);
    return 0;
}

static long handle_add_sus_kstat(void __user *uarg, bool full_clone)
{
    struct st_susfs_sus_kstat info;
    struct sus_kstat_node *node;

    if (copy_from_user(&info, uarg, sizeof(info)))
        return -EFAULT;

    /* Check for existing entry to update */
    spin_lock(&sm_sus_lock);
    list_for_each_entry(node, &sm_sus_kstats, list) {
        if (!strncmp(node->target_pathname, info.target_pathname,
                     SUSFS_MAX_LEN_PATHNAME)) {
            /* Update existing */
            node->spoofed_ino = info.spoofed_ino;
            node->spoofed_dev = info.spoofed_dev;
            node->spoofed.size  = info.spoofed_size;
            node->spoofed.nlink = info.spoofed_nlink;
            node->spoofed.blksize = info.spoofed_blksize;
            node->spoofed.blocks  = info.spoofed_blocks;
            spin_unlock(&sm_sus_lock);
            goto done;
        }
    }
    spin_unlock(&sm_sus_lock);

    node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node) return -ENOMEM;

    strlcpy(node->target_pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME);
    node->spoofed_ino       = info.spoofed_ino;
    node->spoofed_dev       = info.spoofed_dev;
    node->spoofed.size      = info.spoofed_size;
    node->spoofed.nlink     = info.spoofed_nlink;
    node->spoofed.blksize   = info.spoofed_blksize;
    node->spoofed.blocks    = info.spoofed_blocks;

    spin_lock(&sm_sus_lock);
    list_add_tail(&node->list, &sm_sus_kstats);
    spin_unlock(&sm_sus_lock);

done:
    sm_dbg("add_sus_kstat: %s ino=%llu", info.target_pathname, info.spoofed_ino);
    info.err = 0;
    if (copy_to_user(uarg, &info, sizeof(info)))
        return -EFAULT;
    return 0;
}

static long handle_add_sus_map(void __user *uarg)
{
    struct st_susfs_sus_map info;
    struct sus_map_node *node;

    if (copy_from_user(&info, uarg, sizeof(info)))
        return -EFAULT;

    node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node) return -ENOMEM;

    strlcpy(node->pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME);

    spin_lock(&sm_sus_lock);
    list_add_tail(&node->list, &sm_sus_maps);
    spin_unlock(&sm_sus_lock);

    info.err = 0;
    if (copy_to_user(uarg, &info, sizeof(info)))
        return -EFAULT;

    sm_dbg("add_sus_map: %s", node->pathname);
    return 0;
}

static long handle_add_open_redirect(void __user *uarg)
{
    struct st_susfs_open_redirect info;
    struct sus_open_redirect_node *node;

    if (copy_from_user(&info, uarg, sizeof(info)))
        return -EFAULT;

    node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node) return -ENOMEM;

    strlcpy(node->target,   info.target_pathname,     SUSFS_MAX_LEN_PATHNAME);
    strlcpy(node->redirect, info.redirected_pathname,  SUSFS_MAX_LEN_PATHNAME);

    spin_lock(&sm_sus_lock);
    list_add_tail(&node->list, &sm_open_redirects);
    spin_unlock(&sm_sus_lock);

    info.err = 0;
    if (copy_to_user(uarg, &info, sizeof(info)))
        return -EFAULT;

    sm_dbg("add_open_redirect: %s -> %s", node->target, node->redirect);
    return 0;
}

static long handle_set_uname(void __user *uarg)
{
    struct st_susfs_uname info;
    struct new_utsname *uts;
    struct rw_semaphore *uts_sem_ptr;

    if (copy_from_user(&info, uarg, sizeof(info)))
        return -EFAULT;

    uts_sem_ptr = (struct rw_semaphore *)kallsyms_lookup_name("uts_sem");
    uts = init_utsname();

    if (uts_sem_ptr)
        down_write(uts_sem_ptr);

    if (info.sysname[0])  strlcpy(uts->sysname,  info.sysname,  __NEW_UTS_LEN);
    if (info.release[0])  strlcpy(uts->release,  info.release,  __NEW_UTS_LEN);
    if (info.version[0])  strlcpy(uts->version,  info.version,  __NEW_UTS_LEN);
    if (info.machine[0])  strlcpy(uts->machine,  info.machine,  __NEW_UTS_LEN);
    if (info.nodename[0]) strlcpy(uts->nodename, info.nodename, __NEW_UTS_LEN);

    if (uts_sem_ptr)
        up_write(uts_sem_ptr);

    info.err = 0;
    if (copy_to_user(uarg, &info, sizeof(info)))
        return -EFAULT;

    sm_info("set_uname: release=%s", info.release);
    return 0;
}

static long handle_enable_log(void __user *uarg)
{
    struct st_susfs_enable_log info;

    if (copy_from_user(&info, uarg, sizeof(info)))
        return -EFAULT;

    sm_log_enabled = !!info.enabled;
    info.err = 0;
    copy_to_user(uarg, &info, sizeof(info));
    return 0;
}

static long handle_show(void __user *uarg)
{
    struct st_susfs_show info;

    if (copy_from_user(&info, uarg, sizeof(info)))
        return -EFAULT;

    strlcpy(info.result, SUSFS_VERSION, sizeof(info.result));
    info.err = 0;

    if (copy_to_user(uarg, &info, sizeof(info)))
        return -EFAULT;
    return 0;
}

/* ── Our reboot hook ── */
static asmlinkage long sm_sys_reboot(int magic1, int magic2,
                                      unsigned int cmd, void __user *arg)
{
    /* Check for SUSFS magic numbers */
    if ((unsigned int)magic1 == KSU_INSTALL_MAGIC1 &&
        (unsigned int)magic2 == SUSFS_MAGIC) {

        sm_dbg("susfs cmd=0x%x", cmd);

        switch (cmd) {
        case CMD_SUSFS_ADD_SUS_PATH:
            return handle_add_sus_path(arg, false);
        case CMD_SUSFS_ADD_SUS_PATH_LOOP:
            return handle_add_sus_path(arg, true);
        case CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU:
            return handle_hide_sus_mnts(arg);
        case CMD_SUSFS_ADD_SUS_KSTAT:
        case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY:
            return handle_add_sus_kstat(arg, false);
        case CMD_SUSFS_UPDATE_SUS_KSTAT:
        case CMD_SUSFS_UPDATE_SUS_KSTAT_FULL:
            return handle_add_sus_kstat(arg, true);
        case CMD_SUSFS_ADD_SUS_MAP:
            return handle_add_sus_map(arg);
        case CMD_SUSFS_ADD_OPEN_REDIRECT:
            return handle_add_open_redirect(arg);
        case CMD_SUSFS_SET_UNAME:
            return handle_set_uname(arg);
        case CMD_SUSFS_ENABLE_LOG:
            return handle_enable_log(arg);
        case CMD_SUSFS_SHOW:
            return handle_show(arg);
        default:
            sm_err("unknown susfs cmd=0x%x", cmd);
            return -EINVAL;
        }
    }

    /* Not a SUSFS call — pass through to real reboot */
    return orig_sys_reboot(magic1, magic2, cmd, arg);
}

/* ── Init / exit ── */
int sm_syscall_hook_init(void)
{
    unsigned long ksym;

    /* Resolve memory protection functions directly */
    _set_memory_rw = (set_mem_rw_fn_t)kallsyms_lookup_name("set_memory_rw");
    _set_memory_ro = (set_mem_ro_fn_t)kallsyms_lookup_name("set_memory_ro");

    if (!_set_memory_rw || !_set_memory_ro) {
        sm_err("cannot find set_memory_rw/ro — aborting syscall hook");
        return -ENOENT;
    }

    /* Find syscall table */
    ksym = kallsyms_lookup_name("sys_call_table");
    if (!ksym) {
        sm_err("cannot find sys_call_table");
        return -ENOENT;
    }
    syscall_table = (unsigned long *)ksym;

    /* Save original and install hook */
    orig_sys_reboot = (orig_reboot_t)syscall_table[__NR_reboot];

    make_rw((unsigned long)&syscall_table[__NR_reboot]);
    syscall_table[__NR_reboot] = (unsigned long)sm_sys_reboot;
    make_ro((unsigned long)&syscall_table[__NR_reboot]);

    sm_info("syscall hook installed (NR_reboot=%d)", __NR_reboot);
    return 0;
}

void sm_syscall_hook_exit(void)
{
    if (!syscall_table || !orig_sys_reboot)
        return;

    make_rw((unsigned long)&syscall_table[__NR_reboot]);
    syscall_table[__NR_reboot] = (unsigned long)orig_sys_reboot;
    make_ro((unsigned long)&syscall_table[__NR_reboot]);

    sm_info("syscall hook removed");
}
