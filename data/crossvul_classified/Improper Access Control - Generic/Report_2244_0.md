# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2244_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2244_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 873-914 of the vulnerable file.

	struct mount *mnt;
	int err;

	mnt = alloc_vfsmnt(old->mnt_devname);
	if (!mnt)
		return ERR_PTR(-ENOMEM);

	if (flag & (CL_SLAVE | CL_PRIVATE | CL_SHARED_TO_SLAVE))
		mnt->mnt_group_id = 0; /* not a peer of original */
	else
		mnt->mnt_group_id = old->mnt_group_id;

	if ((flag & CL_MAKE_SHARED) && !mnt->mnt_group_id) {
		err = mnt_alloc_group_id(mnt);
		if (err)
			goto out_free;
	}

	mnt->mnt.mnt_flags = old->mnt.mnt_flags & ~(MNT_WRITE_HOLD|MNT_MARKED);
	/* Don't allow unprivileged users to change mount flags */
	if ((flag & CL_UNPRIVILEGED) && (mnt->mnt.mnt_flags & MNT_READONLY))
		mnt->mnt.mnt_flags |= MNT_LOCK_READONLY;

	/* Don't allow unprivileged users to reveal what is under a mount */
	if ((flag & CL_UNPRIVILEGED) && list_empty(&old->mnt_expire))
		mnt->mnt.mnt_flags |= MNT_LOCKED;

	atomic_inc(&sb->s_active);
	mnt->mnt.mnt_sb = sb;
	mnt->mnt.mnt_root = dget(root);
	mnt->mnt_mountpoint = mnt->mnt.mnt_root;
	mnt->mnt_parent = mnt;
	lock_mount_hash();
	list_add_tail(&mnt->mnt_instance, &sb->s_mounts);
	unlock_mount_hash();

	if ((flag & CL_SLAVE) ||
	    ((flag & CL_SHARED_TO_SLAVE) && IS_MNT_SHARED(old))) {
		list_add(&mnt->mnt_slave, &old->mnt_slave_list);
		mnt->mnt_master = old;
		CLEAR_MNT_SHARED(mnt);
	} else if (!(flag & CL_PRIVATE)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -890,8 +890,21 @@
 
 	mnt->mnt.mnt_flags = old->mnt.mnt_flags & ~(MNT_WRITE_HOLD|MNT_MARKED);
 	/* Don't allow unprivileged users to change mount flags */
-	if ((flag & CL_UNPRIVILEGED) && (mnt->mnt.mnt_flags & MNT_READONLY))
-		mnt->mnt.mnt_flags |= MNT_LOCK_READONLY;
+	if (flag & CL_UNPRIVILEGED) {
+		mnt->mnt.mnt_flags |= MNT_LOCK_ATIME;
+
+		if (mnt->mnt.mnt_flags & MNT_READONLY)
+			mnt->mnt.mnt_flags |= MNT_LOCK_READONLY;
+
+		if (mnt->mnt.mnt_flags & MNT_NODEV)
+			mnt->mnt.mnt_flags |= MNT_LOCK_NODEV;
+
+		if (mnt->mnt.mnt_flags & MNT_NOSUID)
+			mnt->mnt.mnt_flags |= MNT_LOCK_NOSUID;
+
+		if (mnt->mnt.mnt_flags & MNT_NOEXEC)
+			mnt->mnt.mnt_flags |= MNT_LOCK_NOEXEC;
+	}
 
 	/* Don't allow unprivileged users to reveal what is under a mount */
 	if ((flag & CL_UNPRIVILEGED) && list_empty(&old->mnt_expire))
@@ -1931,6 +1944,23 @@
 	    !(mnt_flags & MNT_READONLY)) {
 		return -EPERM;
 	}
+	if ((mnt->mnt.mnt_flags & MNT_LOCK_NODEV) &&
+	    !(mnt_flags & MNT_NODEV)) {
+		return -EPERM;
+	}
+	if ((mnt->mnt.mnt_flags & MNT_LOCK_NOSUID) &&
+	    !(mnt_flags & MNT_NOSUID)) {
+		return -EPERM;
+	}
+	if ((mnt->mnt.mnt_flags & MNT_LOCK_NOEXEC) &&
+	    !(mnt_flags & MNT_NOEXEC)) {
+		return -EPERM;
+	}
+	if ((mnt->mnt.mnt_flags & MNT_LOCK_ATIME) &&
+	    ((mnt->mnt.mnt_flags & MNT_ATIME_MASK) != (mnt_flags & MNT_ATIME_MASK))) {
+		return -EPERM;
+	}
+
 	err = security_sb_remount(sb, data);
 	if (err)
 		return err;
@@ -2129,7 +2159,7 @@
 		 */
 		if (!(type->fs_flags & FS_USERNS_DEV_MOUNT)) {
 			flags |= MS_NODEV;
-			mnt_flags |= MNT_NODEV;
+			mnt_flags |= MNT_NODEV | MNT_LOCK_NODEV;
 		}
 	}
 
```
