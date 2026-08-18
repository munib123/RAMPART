# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2287_6
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2287_6`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1051-1091 of the vulnerable file.

		return 0;
	} else {
		return do_flock(file, cmd, fl);
	}
}

const struct file_operations gfs2_file_fops = {
	.llseek		= gfs2_llseek,
	.read		= new_sync_read,
	.read_iter	= generic_file_read_iter,
	.write		= new_sync_write,
	.write_iter	= gfs2_file_write_iter,
	.unlocked_ioctl	= gfs2_ioctl,
	.mmap		= gfs2_mmap,
	.open		= gfs2_open,
	.release	= gfs2_release,
	.fsync		= gfs2_fsync,
	.lock		= gfs2_lock,
	.flock		= gfs2_flock,
	.splice_read	= generic_file_splice_read,
	.splice_write	= generic_file_splice_write,
	.setlease	= gfs2_setlease,
	.fallocate	= gfs2_fallocate,
};

const struct file_operations gfs2_dir_fops = {
	.iterate	= gfs2_readdir,
	.unlocked_ioctl	= gfs2_ioctl,
	.open		= gfs2_open,
	.release	= gfs2_release,
	.fsync		= gfs2_fsync,
	.lock		= gfs2_lock,
	.flock		= gfs2_flock,
	.llseek		= default_llseek,
};

#endif /* CONFIG_GFS2_FS_LOCKING_DLM */

const struct file_operations gfs2_file_fops_nolock = {
	.llseek		= gfs2_llseek,
	.read		= new_sync_read,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1068,7 +1068,7 @@
 	.lock		= gfs2_lock,
 	.flock		= gfs2_flock,
 	.splice_read	= generic_file_splice_read,
-	.splice_write	= generic_file_splice_write,
+	.splice_write	= iter_file_splice_write,
 	.setlease	= gfs2_setlease,
 	.fallocate	= gfs2_fallocate,
 };
@@ -1098,7 +1098,7 @@
 	.release	= gfs2_release,
 	.fsync		= gfs2_fsync,
 	.splice_read	= generic_file_splice_read,
-	.splice_write	= generic_file_splice_write,
+	.splice_write	= iter_file_splice_write,
 	.setlease	= generic_setlease,
 	.fallocate	= gfs2_fallocate,
 };
```
