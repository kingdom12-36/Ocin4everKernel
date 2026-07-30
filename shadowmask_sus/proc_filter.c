// SPDX-License-Identifier: GPL-2.0
// proc_filter.c — hook /proc/pid/maps and /proc/pid/mountinfo seq_file
//
// Replaces the seq_operations.show() pointers for maps and mountinfo
// with wrappers that filter out hidden paths/mounts.
// Uses kallsyms to find the structs; set_memory_rw to patch .rodata.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/mnt_namespace.h>
#include <linux/nsproxy.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include "shadowmask_sus.h"

/* ── Saved originals ── */
typedef int (*seq_show_fn)(struct seq_file *m, void *v);

static seq_show_fn orig_maps_show;
static seq_show_fn orig_mountinfo_show;
static seq_show_fn orig_mounts_show;

static struct seq_operations *maps_op;
static struct seq_operations *mountinfo_op;
static struct seq_operations *mounts_op;

/* ── Helpers ── */

/* Returns true if the current process is a regular app (uid >= 10000) */
static bool is_app_process(void)
{
    return from_kuid_munged(&init_user_ns, current_uid()) >= 10000;
}

/* Check if a path string contains a hidden sus_path */
bool sm_is_path_hidden(const char *path)
{
    struct sus_path_node *node;
    bool found = false;

    if (!path || !*path)
        return false;

    spin_lock(&sm_sus_lock);
    list_for_each_entry(node, &sm_sus_paths, list) {
        if (strnstr(path, node->pathname, SUSFS_MAX_LEN_PATHNAME)) {
            found = true;
            break;
        }
    }
    spin_unlock(&sm_sus_lock);
    return found;
}

/* Check if a path matches a hidden map entry */
bool sm_is_map_hidden(const char *path)
{
    struct sus_map_node *node;
    bool found = false;

    if (!path || !*path)
        return false;

    spin_lock(&sm_sus_lock);
    list_for_each_entry(node, &sm_sus_maps, list) {
        if (strnstr(path, node->pathname, SUSFS_MAX_LEN_PATHNAME)) {
            found = true;
            break;
        }
    }
    spin_unlock(&sm_sus_lock);

    /* Also check sus_paths for map filtering */
    if (!found)
        found = sm_is_path_hidden(path);

    return found;
}

/* ── /proc/pid/maps filter ── */
/*
 * The seq_file for /proc/pid/maps writes one VMA per call to show().
 * We intercept, capture the output into a temporary buffer, then
 * check if the path in that line is hidden — if so, suppress it.
 */

struct sm_maps_ctx {
    struct seq_file *real_m;
    char             buf[PATH_MAX + 256];
    size_t           len;
    bool             suppress;
};

/* We temporarily redirect seq_file output to our buffer */
static int maps_show_filter(struct seq_file *m, void *v)
{
    /* Use a shadow seq_file approach:
     * Call the original show, then scan the newly written bytes.
     * If the line contains a hidden path, remove those bytes. */

    size_t before;
    size_t after;
    char  *line_start;
    char  *newline;
    char   line_copy[PATH_MAX + 128];
    int    ret;

    if (!is_app_process())
        return orig_maps_show(m, v);

    before = m->count;
    ret = orig_maps_show(m, v);
    after  = m->count;

    if (ret || after <= before)
        return ret;

    /* Examine the newly written line */
    line_start = m->buf + before;
    newline    = memchr(line_start, '\n', after - before);

    /* Copy line for inspection (don't trust the seq_file buffer directly) */
    {
        size_t line_len = newline ? (size_t)(newline - line_start + 1)
                                  : (after - before);
        if (line_len >= sizeof(line_copy))
            return ret;

        memcpy(line_copy, line_start, line_len);
        line_copy[line_len] = '\0';

        /* Format: addr perm offset dev ino [path] */
        /* Find the 6th field (path) — skip 5 spaces/tabs */
        {
            int  spaces = 0;
            char *p = line_copy;
            while (*p && spaces < 5) {
                if (*p == ' ' || *p == '\t') {
                    spaces++;
                    while (*(p+1) == ' ' || *(p+1) == '\t') p++;
                }
                p++;
            }
            /* p now points at the path (if present) */
            if (spaces == 5 && *p && *p != '\n') {
                char *end = strchr(p, '\n');
                if (end) *end = '\0';
                if (sm_is_map_hidden(p)) {
                    /* Erase the line from the seq_file buffer */
                    m->count = before;
                    sm_dbg("maps: suppressed %s", p);
                }
            }
        }
    }
    return ret;
}

/* ── /proc/pid/mountinfo + /proc/mounts filter ── */
/*
 * mountinfo lines look like:
 *   36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,...
 * We check if the mount point or source path is a sus_path/sus_mount.
 */

static bool mountinfo_line_is_hidden(const char *line, size_t len)
{
    /* Quick check: look for known root-related strings */
    static const char * const sus_markers[] = {
        "/data/adb",
        "/.shadowmask",
        "/.magisk",
        "/sbin/.magisk",
        "/debug_ramdisk",
        "KSU",
        "shadowmask",
        NULL,
    };
    const char **m;

    if (!sm_hide_sus_mnts)
        return false;

    if (!is_app_process())
        return false;

    /* Check built-in markers */
    for (m = sus_markers; *m; m++) {
        if (strnstr(line, *m, len))
            return true;
    }

    /* Check user-added sus_paths */
    {
        struct sus_path_node *node;
        spin_lock(&sm_sus_lock);
        list_for_each_entry(node, &sm_sus_paths, list) {
            if (strnstr(line, node->pathname, len)) {
                spin_unlock(&sm_sus_lock);
                return true;
            }
        }
        spin_unlock(&sm_sus_lock);
    }

    return false;
}

static int mountinfo_show_filter(struct seq_file *m, void *v)
{
    size_t before, after;
    int    ret;

    before = m->count;
    ret    = orig_mountinfo_show(m, v);
    after  = m->count;

    if (ret || after <= before)
        return ret;

    {
        char *line = m->buf + before;
        size_t line_len = after - before;

        if (mountinfo_line_is_hidden(line, line_len)) {
            m->count = before;
            sm_dbg("mountinfo: suppressed line");
        }
    }
    return ret;
}

static int mounts_show_filter(struct seq_file *m, void *v)
{
    size_t before, after;
    int    ret;

    before = m->count;
    ret    = orig_mounts_show(m, v);
    after  = m->count;

    if (ret || after <= before)
        return ret;

    {
        char *line = m->buf + before;
        size_t line_len = after - before;

        if (mountinfo_line_is_hidden(line, line_len)) {
            m->count = before;
            sm_dbg("mounts: suppressed line");
        }
    }
    return ret;
}

/* ── Patch a seq_operations.show pointer ── */

typedef int (*set_mem_rw_t)(unsigned long, int);
typedef int (*set_mem_ro_t)(unsigned long, int);
static set_mem_rw_t _smrw;
static set_mem_ro_t _smro;

static void patch_seq_show(struct seq_operations *op,
                            seq_show_fn           new_show,
                            seq_show_fn          *saved)
{
    unsigned long page;

    if (!op) return;

    *saved = op->show;
    page   = ((unsigned long)&op->show) & PAGE_MASK;

    if (_smrw) _smrw(page, 1);
    op->show = new_show;
    if (_smro) _smro(page, 1);
}

static void unpatch_seq_show(struct seq_operations *op, seq_show_fn orig)
{
    unsigned long page;

    if (!op || !orig) return;

    page = ((unsigned long)&op->show) & PAGE_MASK;

    if (_smrw) _smrw(page, 1);
    op->show = orig;
    if (_smro) _smro(page, 1);
}

/* ── Init / exit ── */
int sm_proc_hook_init(void)
{
    _smrw = (set_mem_rw_t)kallsyms_lookup_name("set_memory_rw");
    _smro = (set_mem_ro_t)kallsyms_lookup_name("set_memory_ro");

    /* /proc/pid/maps */
    maps_op = (struct seq_operations *)
        kallsyms_lookup_name("proc_pid_maps_op");
    if (maps_op) {
        patch_seq_show(maps_op, maps_show_filter, &orig_maps_show);
        sm_info("proc maps hook installed");
    } else {
        sm_err("proc_pid_maps_op not found — maps filter disabled");
    }

    /* /proc/pid/mountinfo */
    mountinfo_op = (struct seq_operations *)
        kallsyms_lookup_name("mountinfo_op");
    if (mountinfo_op) {
        patch_seq_show(mountinfo_op, mountinfo_show_filter, &orig_mountinfo_show);
        sm_info("mountinfo hook installed");
    } else {
        sm_err("mountinfo_op not found — mountinfo filter disabled");
    }

    /* /proc/pid/mounts (same data, different format) */
    mounts_op = (struct seq_operations *)
        kallsyms_lookup_name("mounts_op");
    if (mounts_op) {
        patch_seq_show(mounts_op, mounts_show_filter, &orig_mounts_show);
        sm_info("mounts hook installed");
    }

    return 0;
}

void sm_proc_hook_exit(void)
{
    unpatch_seq_show(maps_op,      orig_maps_show);
    unpatch_seq_show(mountinfo_op, orig_mountinfo_show);
    unpatch_seq_show(mounts_op,    orig_mounts_show);
    sm_info("proc hooks removed");
}
