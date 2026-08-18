# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 2306_2
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2306_2`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 668-708 of the vulnerable file.

	struct inode *inode;
	int error;

	f->f_mode = OPEN_FMODE(f->f_flags) | FMODE_LSEEK |
				FMODE_PREAD | FMODE_PWRITE;

	if (unlikely(f->f_flags & O_PATH))
		f->f_mode = FMODE_PATH;

	path_get(&f->f_path);
	inode = f->f_inode = f->f_path.dentry->d_inode;
	if (f->f_mode & FMODE_WRITE) {
		error = __get_file_write_access(inode, f->f_path.mnt);
		if (error)
			goto cleanup_file;
		if (!special_file(inode->i_mode))
			file_take_write(f);
	}

	f->f_mapping = inode->i_mapping;
	file_sb_list_add(f, inode->i_sb);

	if (unlikely(f->f_mode & FMODE_PATH)) {
		f->f_op = &empty_fops;
		return 0;
	}

	f->f_op = fops_get(inode->i_fop);
	if (unlikely(WARN_ON(!f->f_op))) {
		error = -ENODEV;
		goto cleanup_all;
	}

	error = security_file_open(f, cred);
	if (error)
		goto cleanup_all;

	error = break_lease(inode, f->f_flags);
	if (error)
		goto cleanup_all;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -685,7 +685,6 @@
 	}
 
 	f->f_mapping = inode->i_mapping;
-	file_sb_list_add(f, inode->i_sb);
 
 	if (unlikely(f->f_mode & FMODE_PATH)) {
 		f->f_op = &empty_fops;
@@ -724,7 +723,6 @@
 
 cleanup_all:
 	fops_put(f->f_op);
-	file_sb_list_del(f);
 	if (f->f_mode & FMODE_WRITE) {
 		put_write_access(inode);
 		if (!special_file(inode->i_mode)) {
```
