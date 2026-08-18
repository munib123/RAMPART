# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2287_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2287_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 60-85 of the vulnerable file.


static int exofs_flush(struct file *file, fl_owner_t id)
{
	int ret = vfs_fsync(file, 0);
	/* TODO: Flush the OSD target */
	return ret;
}

const struct file_operations exofs_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= new_sync_read,
	.write		= new_sync_write,
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.open		= generic_file_open,
	.release	= exofs_release_file,
	.fsync		= exofs_file_fsync,
	.flush		= exofs_flush,
	.splice_read	= generic_file_splice_read,
	.splice_write	= generic_file_splice_write,
};

const struct inode_operations exofs_file_inode_operations = {
	.setattr	= exofs_setattr,
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -77,7 +77,7 @@
 	.fsync		= exofs_file_fsync,
 	.flush		= exofs_flush,
 	.splice_read	= generic_file_splice_read,
-	.splice_write	= generic_file_splice_write,
+	.splice_write	= iter_file_splice_write,
 };
 
 const struct inode_operations exofs_file_inode_operations = {
```
