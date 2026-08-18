# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 4771_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4771_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 222-262 of the vulnerable file.

	}
	path.mnt = mntget(aio_mnt);

	d_instantiate(path.dentry, inode);
	file = alloc_file(&path, FMODE_READ | FMODE_WRITE, &aio_ring_fops);
	if (IS_ERR(file)) {
		path_put(&path);
		return file;
	}

	file->f_flags = O_RDWR;
	return file;
}

static struct dentry *aio_mount(struct file_system_type *fs_type,
				int flags, const char *dev_name, void *data)
{
	static const struct dentry_operations ops = {
		.d_dname	= simple_dname,
	};
	return mount_pseudo(fs_type, "aio:", NULL, &ops, AIO_RING_MAGIC);
}

/* aio_setup
 *	Creates the slab caches used by the aio routines, panic on
 *	failure as this is done early during the boot sequence.
 */
static int __init aio_setup(void)
{
	static struct file_system_type aio_fs = {
		.name		= "aio",
		.mount		= aio_mount,
		.kill_sb	= kill_anon_super,
	};
	aio_mnt = kern_mount(&aio_fs);
	if (IS_ERR(aio_mnt))
		panic("Failed to create aio fs mount.");

	kiocb_cachep = KMEM_CACHE(aio_kiocb, SLAB_HWCACHE_ALIGN|SLAB_PANIC);
	kioctx_cachep = KMEM_CACHE(kioctx,SLAB_HWCACHE_ALIGN|SLAB_PANIC);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -239,7 +239,12 @@
 	static const struct dentry_operations ops = {
 		.d_dname	= simple_dname,
 	};
-	return mount_pseudo(fs_type, "aio:", NULL, &ops, AIO_RING_MAGIC);
+	struct dentry *root = mount_pseudo(fs_type, "aio:", NULL, &ops,
+					   AIO_RING_MAGIC);
+
+	if (!IS_ERR(root))
+		root->d_sb->s_iflags |= SB_I_NOEXEC;
+	return root;
 }
 
 /* aio_setup
```
