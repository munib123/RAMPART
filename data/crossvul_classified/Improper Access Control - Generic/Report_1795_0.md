# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1795_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1795_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 32-73 of the vulnerable file.


	if (no_data)
		stat.size = 0;

	err = ovl_copy_up_one(parent, dentry, &lowerpath, &stat, attr);

out_dput_parent:
	dput(parent);
	return err;
}

int ovl_setattr(struct dentry *dentry, struct iattr *attr)
{
	int err;
	struct dentry *upperdentry;

	err = ovl_want_write(dentry);
	if (err)
		goto out;

	upperdentry = ovl_dentry_upper(dentry);
	if (upperdentry) {
		mutex_lock(&upperdentry->d_inode->i_mutex);
		err = notify_change(upperdentry, attr, NULL);
		mutex_unlock(&upperdentry->d_inode->i_mutex);
	} else {
		err = ovl_copy_up_last(dentry, attr, false);
	}
	ovl_drop_write(dentry);
out:
	return err;
}

static int ovl_getattr(struct vfsmount *mnt, struct dentry *dentry,
			 struct kstat *stat)
{
	struct path realpath;

	ovl_path_real(dentry, &realpath);
	return vfs_getattr(&realpath, stat);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,13 +49,13 @@
 	if (err)
 		goto out;
 
-	upperdentry = ovl_dentry_upper(dentry);
-	if (upperdentry) {
+	err = ovl_copy_up(dentry);
+	if (!err) {
+		upperdentry = ovl_dentry_upper(dentry);
+
 		mutex_lock(&upperdentry->d_inode->i_mutex);
 		err = notify_change(upperdentry, attr, NULL);
 		mutex_unlock(&upperdentry->d_inode->i_mutex);
-	} else {
-		err = ovl_copy_up_last(dentry, attr, false);
 	}
 	ovl_drop_write(dentry);
 out:
```
