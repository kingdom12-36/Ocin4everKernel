#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/path.h>
#include <linux/fs.h>
#include <linux/stat.h>

char *nomount_handle_dpath(const struct path *path, char *buf, int buflen) { return NULL; }
struct filename *nomount_handle_getname(struct filename *name) { return name; }
int nomount_handle_permission(struct inode *inode, int mask) { return 0; }
bool nomount_spoof_mmap_metadata(struct inode *inode, dev_t *dev, unsigned long *ino) { return false; }
int nomount_handle_iterate_dir(struct file *file, struct dir_context *ctx) { return 0; }
int nomount_handle_getattr(int ret, const struct path *path, struct kstat *stat) { return ret; }
void nomount_spoof_statfs(const struct path *path, struct kstatfs *buf) {}
