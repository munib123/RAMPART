# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5615_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5615_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 2715-2755 of the vulnerable file.

}
EXPORT_SYMBOL_GPL(kern_mount_data);

void kern_unmount(struct vfsmount *mnt)
{
	/* release long term mount so mount point can be released */
	if (!IS_ERR_OR_NULL(mnt)) {
		br_write_lock(&vfsmount_lock);
		real_mount(mnt)->mnt_ns = NULL;
		br_write_unlock(&vfsmount_lock);
		mntput(mnt);
	}
}
EXPORT_SYMBOL(kern_unmount);

bool our_mnt(struct vfsmount *mnt)
{
	return check_mnt(real_mount(mnt));
}

static void *mntns_get(struct task_struct *task)
{
	struct mnt_namespace *ns = NULL;
	struct nsproxy *nsproxy;

	rcu_read_lock();
	nsproxy = task_nsproxy(task);
	if (nsproxy) {
		ns = nsproxy->mnt_ns;
		get_mnt_ns(ns);
	}
	rcu_read_unlock();

	return ns;
}

static void mntns_put(void *ns)
{
	put_mnt_ns(ns);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2732,6 +2732,30 @@
 	return check_mnt(real_mount(mnt));
 }
 
+bool current_chrooted(void)
+{
+	/* Does the current process have a non-standard root */
+	struct path ns_root;
+	struct path fs_root;
+	bool chrooted;
+
+	/* Find the namespace root */
+	ns_root.mnt = &current->nsproxy->mnt_ns->root->mnt;
+	ns_root.dentry = ns_root.mnt->mnt_root;
+	path_get(&ns_root);
+	while (d_mountpoint(ns_root.dentry) && follow_down_one(&ns_root))
+		;
+
+	get_fs_root(current->fs, &fs_root);
+
+	chrooted = !path_equal(&fs_root, &ns_root);
+
+	path_put(&fs_root);
+	path_put(&ns_root);
+
+	return chrooted;
+}
+
 static void *mntns_get(struct task_struct *task)
 {
 	struct mnt_namespace *ns = NULL;
```
