# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 5200_5
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5200_5`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 79-99 of the vulnerable file.

extern void mnt_drop_write_file(struct file *file);
extern void mntput(struct vfsmount *mnt);
extern struct vfsmount *mntget(struct vfsmount *mnt);
extern struct vfsmount *mnt_clone_internal(struct path *path);
extern int __mnt_is_readonly(struct vfsmount *mnt);
extern bool mnt_may_suid(struct vfsmount *mnt);

struct path;
extern struct vfsmount *clone_private_mount(struct path *path);

struct file_system_type;
extern struct vfsmount *vfs_kern_mount(struct file_system_type *type,
				      int flags, const char *name,
				      void *data);

extern void mnt_set_expiry(struct vfsmount *mnt, struct list_head *expiry_list);
extern void mark_mounts_for_expiry(struct list_head *mounts);

extern dev_t name_to_dev_t(const char *name);

#endif /* _LINUX_MOUNT_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -96,4 +96,6 @@
 
 extern dev_t name_to_dev_t(const char *name);
 
+extern unsigned int sysctl_mount_max;
+
 #endif /* _LINUX_MOUNT_H */
```
