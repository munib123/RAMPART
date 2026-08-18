# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2438_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2438_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 660-700 of the vulnerable file.

		goto out_put_workpath;
	}

	if (!ovl_is_allowed_fs_type(upperpath.dentry)) {
		pr_err("overlayfs: filesystem of upperdir is not supported\n");
		goto out_put_workpath;
	}

	if (!ovl_is_allowed_fs_type(lowerpath.dentry)) {
		pr_err("overlayfs: filesystem of lowerdir is not supported\n");
		goto out_put_workpath;
	}

	err = vfs_statfs(&lowerpath, &statfs);
	if (err) {
		pr_err("overlayfs: statfs failed on lowerpath\n");
		goto out_put_workpath;
	}
	ufs->lower_namelen = statfs.f_namelen;

	ufs->upper_mnt = clone_private_mount(&upperpath);
	err = PTR_ERR(ufs->upper_mnt);
	if (IS_ERR(ufs->upper_mnt)) {
		pr_err("overlayfs: failed to clone upperpath\n");
		goto out_put_workpath;
	}

	ufs->lower_mnt = clone_private_mount(&lowerpath);
	err = PTR_ERR(ufs->lower_mnt);
	if (IS_ERR(ufs->lower_mnt)) {
		pr_err("overlayfs: failed to clone lowerpath\n");
		goto out_put_upper_mnt;
	}

	ufs->workdir = ovl_workdir_create(ufs->upper_mnt, workpath.dentry);
	err = PTR_ERR(ufs->workdir);
	if (IS_ERR(ufs->workdir)) {
		pr_err("overlayfs: failed to create directory %s/%s\n",
		       ufs->config.workdir, OVL_WORKDIR_NAME);
		goto out_put_lower_mnt;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -676,6 +676,15 @@
 		goto out_put_workpath;
 	}
 	ufs->lower_namelen = statfs.f_namelen;
+
+	sb->s_stack_depth = max(upperpath.mnt->mnt_sb->s_stack_depth,
+				lowerpath.mnt->mnt_sb->s_stack_depth) + 1;
+
+	err = -EINVAL;
+	if (sb->s_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {
+		pr_err("overlayfs: maximum fs stacking depth exceeded\n");
+		goto out_put_workpath;
+	}
 
 	ufs->upper_mnt = clone_private_mount(&upperpath);
 	err = PTR_ERR(ufs->upper_mnt);
```
