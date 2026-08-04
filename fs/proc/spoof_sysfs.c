// SPDX-License-Identifier: GPL-2.0
/*
 * spoof_sysfs.c — Spoofing P10: hide /sys/module/ksu* from user apps
 */
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include <linux/spoof_helper.h>

static const char * const spoof_denied_sysfs[] = {
    "/sys/module/ksu", "/sys/module/kernelsu",
    "/sys/firmware/verifiedbootstate",
    NULL
};

int spoof_sysfs_check_path(const char *path)
{
    int i;
    if (!path || current_uid().val < 10000 || spoof_is_whitelisted())
        return 0;
    for (i = 0; spoof_denied_sysfs[i]; i++)
        if (!strcmp(path, spoof_denied_sysfs[i])) return -ENOENT;
    return 0;
}
EXPORT_SYMBOL_GPL(spoof_sysfs_check_path);
