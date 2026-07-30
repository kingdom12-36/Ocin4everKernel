/* SPDX-License-Identifier: GPL-2.0
 * shadowmask_sus.h — ShadowMask SUSFS Kernel Module
 *
 * Implements SUSFS hiding features as a loadable kernel module (.ko),
 * compatible with the ksu_susfs userspace tool (same syscall ABI).
 * No kernel source patching required — needs only:
 *   CONFIG_MODULES=y, CONFIG_KALLSYMS_ALL=y, CONFIG_MODULE_SIG not set
 */

#ifndef SHADOWMASK_SUS_H
#define SHADOWMASK_SUS_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/prctl.h>

/* ── SUSFS ABI (must match ksu_susfs userspace tool) ── */
#define KSU_INSTALL_MAGIC1                  0xDEADBEEF
#define KSU_INSTALL_MAGIC2                  0xDEADBEEF   /* reboot magic2 unused */
#define SUSFS_MAGIC                         0xFAFAFAFA

#define SUSFS_MAX_LEN_PATHNAME              256
#define SUSFS_VERSION                       "v2.2.0-lkm"
#define ERR_CMD_NOT_SUPPORTED               126

/* Commands (same values as simonpunk/susfs4ksu kernel patches) */
#define CMD_SUSFS_ADD_SUS_PATH              0x55550
#define CMD_SUSFS_ADD_SUS_PATH_LOOP         0x55553
#define CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU  0x55560
#define CMD_SUSFS_ADD_SUS_KSTAT             0x55570
#define CMD_SUSFS_UPDATE_SUS_KSTAT          0x55571
#define CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY  0x55572
#define CMD_SUSFS_UPDATE_SUS_KSTAT_FULL     0x55574
#define CMD_SUSFS_ADD_SUS_MAP               0x55590
#define CMD_SUSFS_ADD_OPEN_REDIRECT         0x555a0
#define CMD_SUSFS_SET_UNAME                 0x555b0
#define CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG 0x555c0
#define CMD_SUSFS_ENABLE_LOG                0x555d0
#define CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING   0x555e0
#define CMD_SUSFS_SHOW                      0x555f0

/* ── Userspace struct layouts (mirror of ksu_susfs structs) ── */
struct st_susfs_sus_path {
    char  target_pathname[SUSFS_MAX_LEN_PATHNAME];
    int   err;
};

struct st_susfs_sus_mount {
    int   enabled;
    int   err;
};

struct st_susfs_sus_kstat {
    char     target_pathname[SUSFS_MAX_LEN_PATHNAME];
    char     spoofed_pathname[SUSFS_MAX_LEN_PATHNAME];
    uint64_t spoofed_ino;
    uint64_t spoofed_dev;
    uint32_t spoofed_nlink;
    uint32_t spoofed_blksize;
    uint64_t spoofed_size;
    uint64_t spoofed_blocks;
    int64_t  spoofed_atime_tv_sec;
    int64_t  spoofed_mtime_tv_sec;
    int64_t  spoofed_ctime_tv_sec;
    long     spoofed_atime_tv_nsec;
    long     spoofed_mtime_tv_nsec;
    long     spoofed_ctime_tv_nsec;
    int      err;
};

struct st_susfs_sus_map {
    char  target_pathname[SUSFS_MAX_LEN_PATHNAME];
    int   err;
};

struct st_susfs_open_redirect {
    char  target_pathname[SUSFS_MAX_LEN_PATHNAME];
    char  redirected_pathname[SUSFS_MAX_LEN_PATHNAME];
    int   err;
};

struct st_susfs_uname {
    char  sysname[65];
    char  nodename[65];
    char  release[65];
    char  version[65];
    char  machine[65];
    int   err;
};

struct st_susfs_cmdline {
    char  value[4096];
    int   err;
};

struct st_susfs_enable_log {
    int   enabled;
    int   err;
};

struct st_susfs_show {
    char  result[256];
    int   err;
};

/* ── Kernel-side list entries ── */
struct sus_path_node {
    char pathname[SUSFS_MAX_LEN_PATHNAME];
    bool loop;                /* re-applied for each new app process */
    struct list_head list;
};

struct sus_kstat_node {
    char target_pathname[SUSFS_MAX_LEN_PATHNAME];
    struct kstat spoofed;
    uint64_t spoofed_ino;
    uint64_t spoofed_dev;
    struct list_head list;
};

struct sus_map_node {
    char pathname[SUSFS_MAX_LEN_PATHNAME];
    struct list_head list;
};

struct sus_open_redirect_node {
    char target[SUSFS_MAX_LEN_PATHNAME];
    char redirect[SUSFS_MAX_LEN_PATHNAME];
    struct list_head list;
};

/* ── Module state ── */
extern struct list_head sm_sus_paths;
extern struct list_head sm_sus_kstats;
extern struct list_head sm_sus_maps;
extern struct list_head sm_open_redirects;
extern spinlock_t       sm_sus_lock;
extern bool             sm_hide_sus_mnts;
extern bool             sm_log_enabled;

/* ── Helpers ── */
#define SM_TAG  "shadowmask_sus"

#define sm_info(fmt, ...) \
    pr_info(SM_TAG ": " fmt "\n", ##__VA_ARGS__)

#define sm_dbg(fmt, ...) \
    do { if (sm_log_enabled) pr_info(SM_TAG " [dbg]: " fmt "\n", ##__VA_ARGS__); } while (0)

#define sm_err(fmt, ...) \
    pr_err(SM_TAG " [err]: " fmt "\n", ##__VA_ARGS__)

/* Internal function declarations */
int  sm_proc_hook_init(void);
void sm_proc_hook_exit(void);
int  sm_syscall_hook_init(void);
void sm_syscall_hook_exit(void);
bool sm_is_path_hidden(const char *path);
bool sm_is_map_hidden(const char *path);

#endif /* SHADOWMASK_SUS_H */
