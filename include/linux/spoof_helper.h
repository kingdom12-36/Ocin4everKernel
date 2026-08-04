/* SPDX-License-Identifier: GPL-2.0 */
/*
 * spoof_helper.h — Manual kernel-level spoofing helpers (no module needed)
 * Included by: task_mmu.c, array.c, base.c, cmdline.c, binder.c, avc.c
 */
#ifndef _LINUX_SPOOF_HELPER_H
#define _LINUX_SPOOF_HELPER_H

#include <linux/string.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include <linux/cred.h> 

static const char * const spoof_hidden_map_paths[] = {
    "/magisk", "/.magisk", "/data/adb/magisk", "/data/adb/ksu",
    "/data/adb/ap", "/data/adb/modules", "/@ksu", "/dev/sfd",
    "zygisk", "injector", "libzygisk", "magiskd", "ksuinit", NULL
};

static const char * const spoof_hidden_mount_paths[] = {
    "/magisk", "/.magisk", "/data/adb/magisk", "/data/adb/ksu",
    "/data/adb/ap", "worker:", "@ksu", "KSU",
    "/sbin/.magisk", "/dev/.magisk", NULL
};

static const char * const spoof_hidden_selinux_types[] = {
    "ksu_file", "ksu_exec", "ksu_data_file", "ksu_tmpfs",
    "adb_data_file", NULL
};

static const char * const spoof_selinux_suppress_sources[] = {
    "fsck_untrusted", NULL
};

static const char * const spoof_whitelist_comms[] = {
    "init", "ueventd", "logd", "adbd", "vold", "installd",
    "surfaceflinger", "zygote", "zygote64", "lmkd", "servicemanager", NULL
};

static inline bool spoof_is_whitelisted(void)
{
    int i; char comm[TASK_COMM_LEN];
    get_task_comm(comm, current);
    for (i = 0; spoof_whitelist_comms[i]; i++)
        if (!strncmp(comm, spoof_whitelist_comms[i],
                     strlen(spoof_whitelist_comms[i])))
            return true;
    return false;
}

static inline bool spoof_should_hide_map_entry(const char *path)
{
    int i;
    if (!path || IS_ERR_VALUE((unsigned long)path)) return false;
    if (spoof_is_whitelisted()) return false;
    for (i = 0; spoof_hidden_map_paths[i]; i++)
        if (strstr(path, spoof_hidden_map_paths[i])) return true;
    return false;
}

static inline bool spoof_should_hide_mount(const char *p)
{
    int i;
    if (!p || IS_ERR_VALUE((unsigned long)p)) return false;
    if (spoof_is_whitelisted()) return false;
    for (i = 0; spoof_hidden_mount_paths[i]; i++)
        if (strstr(p, spoof_hidden_mount_paths[i])) return true;
    return false;
}

static inline bool spoof_selinux_suppress_audit(const char *sctx,
                                                  const char *tctx)
{
    int i;
    if (!sctx || !tctx) return false;
    for (i = 0; spoof_hidden_selinux_types[i]; i++)
        if (strstr(tctx, spoof_hidden_selinux_types[i])) return true;
    for (i = 0; spoof_selinux_suppress_sources[i]; i++)
        if (strstr(sctx, spoof_selinux_suppress_sources[i])) return true;
    return false;
}

static inline bool spoof_should_spoof_uname(void)
{
    if (spoof_is_whitelisted()) return false;
    return (current_uid().val >= 10000);
}

#endif /* _LINUX_SPOOF_HELPER_H */
