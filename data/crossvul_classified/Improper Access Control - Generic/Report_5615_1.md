# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5615_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5615_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 33-53 of the vulnerable file.


static inline void get_fs_pwd(struct fs_struct *fs, struct path *pwd)
{
	spin_lock(&fs->lock);
	*pwd = fs->pwd;
	path_get(pwd);
	spin_unlock(&fs->lock);
}

static inline void get_fs_root_and_pwd(struct fs_struct *fs, struct path *root,
				       struct path *pwd)
{
	spin_lock(&fs->lock);
	*root = fs->root;
	path_get(root);
	*pwd = fs->pwd;
	path_get(pwd);
	spin_unlock(&fs->lock);
}

#endif /* _LINUX_FS_STRUCT_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -50,4 +50,6 @@
 	spin_unlock(&fs->lock);
 }
 
+extern bool current_chrooted(void);
+
 #endif /* _LINUX_FS_STRUCT_H */
```
