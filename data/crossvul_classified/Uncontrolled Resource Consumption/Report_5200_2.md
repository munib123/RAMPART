# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 5200_2
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5200_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 9-49 of the vulnerable file.

 */

#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/capability.h>
#include <linux/mnt_namespace.h>
#include <linux/user_namespace.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/idr.h>
#include <linux/init.h>		/* init_rootfs */
#include <linux/fs_struct.h>	/* get_fs_root et.al. */
#include <linux/fsnotify.h>	/* fsnotify_vfsmount_delete */
#include <linux/uaccess.h>
#include <linux/proc_ns.h>
#include <linux/magic.h>
#include <linux/bootmem.h>
#include <linux/task_work.h>
#include "pnode.h"
#include "internal.h"

static unsigned int m_hash_mask __read_mostly;
static unsigned int m_hash_shift __read_mostly;
static unsigned int mp_hash_mask __read_mostly;
static unsigned int mp_hash_shift __read_mostly;

static __initdata unsigned long mhash_entries;
static int __init set_mhash_entries(char *str)
{
	if (!str)
		return 0;
	mhash_entries = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("mhash_entries=", set_mhash_entries);

static __initdata unsigned long mphash_entries;
static int __init set_mphash_entries(char *str)
{
	if (!str)
		return 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,6 +26,9 @@
 #include <linux/task_work.h>
 #include "pnode.h"
 #include "internal.h"
+
+/* Maximum number of mounts in a mount namespace */
+unsigned int sysctl_mount_max __read_mostly = 100000;
 
 static unsigned int m_hash_mask __read_mostly;
 static unsigned int m_hash_shift __read_mostly;
@@ -899,6 +902,9 @@
 
 	list_splice(&head, n->list.prev);
 
+	n->mounts += n->pending_mounts;
+	n->pending_mounts = 0;
+
 	attach_shadowed(mnt, parent, shadows);
 	touch_mnt_namespace(n);
 }
@@ -1419,11 +1425,16 @@
 		propagate_umount(&tmp_list);
 
 	while (!list_empty(&tmp_list)) {
+		struct mnt_namespace *ns;
 		bool disconnect;
 		p = list_first_entry(&tmp_list, struct mount, mnt_list);
 		list_del_init(&p->mnt_expire);
 		list_del_init(&p->mnt_list);
-		__touch_mnt_namespace(p->mnt_ns);
+		ns = p->mnt_ns;
+		if (ns) {
+			ns->mounts--;
+			__touch_mnt_namespace(ns);
+		}
 		p->mnt_ns = NULL;
 		if (how & UMOUNT_SYNC)
 			p->mnt.mnt_flags |= MNT_SYNC_UMOUNT;
@@ -1840,6 +1851,28 @@
 	return 0;
 }
 
+int count_mounts(struct mnt_namespace *ns, struct mount *mnt)
+{
+	unsigned int max = READ_ONCE(sysctl_mount_max);
+	unsigned int mounts = 0, old, pending, sum;
+	struct mount *p;
+
+	for (p = mnt; p; p = next_mnt(p, mnt))
+		mounts++;
+
+	old = ns->mounts;
+	pending = ns->pending_mounts;
+	sum = old + pending;
+	if ((old > sum) ||
+	    (pending > sum) ||
+	    (max < sum) ||
+	    (mounts > (max - sum)))
+		return -ENOSPC;
+
+	ns->pending_mounts = pending + mounts;
+	return 0;
+}
+
 /*
  *  @source_mnt : mount tree to be attached
  *  @nd         : place the mount tree @source_mnt is attached
@@ -1909,9 +1942,17 @@
 			struct path *parent_path)
 {
 	HLIST_HEAD(tree_list);
+	struct mnt_namespace *ns = dest_mnt->mnt_ns;
 	struct mount *child, *p;
 	struct hlist_node *n;
 	int err;
+
+	/* Is there space to add these mounts to the mount namespace? */
+	if (!parent_path) {
+		err = count_mounts(ns, source_mnt);
+		if (err)
+			goto out;
+	}
 
 	if (IS_MNT_SHARED(dest_mnt)) {
 		err = invent_group_ids(source_mnt, true);
@@ -1949,11 +1990,13 @@
  out_cleanup_ids:
 	while (!hlist_empty(&tree_list)) {
 		child = hlist_entry(tree_list.first, struct mount, mnt_hash);
+		child->mnt_parent->mnt_ns->pending_mounts = 0;
 		umount_tree(child, UMOUNT_SYNC);
 	}
 	unlock_mount_hash();
 	cleanup_group_ids(source_mnt, NULL);
  out:
+	ns->pending_mounts = 0;
 	return err;
 }
 
@@ -2776,6 +2819,8 @@
 	new_ns->event = 0;
 	new_ns->user_ns = get_user_ns(user_ns);
 	new_ns->ucounts = ucounts;
+	new_ns->mounts = 0;
+	new_ns->pending_mounts = 0;
 	return new_ns;
 }
 
@@ -2825,6 +2870,7 @@
 	q = new;
 	while (p) {
 		q->mnt_ns = new_ns;
+		new_ns->mounts++;
 		if (new_fs) {
 			if (&p->mnt == new_fs->root.mnt) {
 				new_fs->root.mnt = mntget(&q->mnt);
@@ -2863,6 +2909,7 @@
 		struct mount *mnt = real_mount(m);
 		mnt->mnt_ns = new_ns;
 		new_ns->root = mnt;
+		new_ns->mounts++;
 		list_add(&mnt->mnt_list, &new_ns->list);
 	} else {
 		mntput(m);
```
