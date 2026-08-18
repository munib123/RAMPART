# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 2241_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2241_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 2239-2279 of the vulnerable file.

			error = -ENOMEM;
			mutex_unlock(&dir->d_inode->i_mutex);
			goto out;
		}
		dentry = lookup_real(dir->d_inode, dentry, nd->flags);
		error = PTR_ERR(dentry);
		if (IS_ERR(dentry)) {
			mutex_unlock(&dir->d_inode->i_mutex);
			goto out;
		}
	}
	mutex_unlock(&dir->d_inode->i_mutex);

done:
	if (!dentry->d_inode || d_is_negative(dentry)) {
		error = -ENOENT;
		dput(dentry);
		goto out;
	}
	path->dentry = dentry;
	path->mnt = mntget(nd->path.mnt);
	if (should_follow_link(dentry, nd->flags & LOOKUP_FOLLOW))
		return 1;
	follow_mount(path);
	error = 0;
out:
	terminate_walk(nd);
	return error;
}

/**
 * path_mountpoint - look up a path to be umounted
 * @dfd:	directory file descriptor to start walk from
 * @name:	full pathname to walk
 * @path:	pointer to container for result
 * @flags:	lookup flags
 *
 * Look up the given name, but don't attempt to revalidate the last component.
 * Returns 0 and "path" will be valid on success; Returns error otherwise.
 */
static int
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2256,9 +2256,10 @@
 		goto out;
 	}
 	path->dentry = dentry;
-	path->mnt = mntget(nd->path.mnt);
+	path->mnt = nd->path.mnt;
 	if (should_follow_link(dentry, nd->flags & LOOKUP_FOLLOW))
 		return 1;
+	mntget(path->mnt);
 	follow_mount(path);
 	error = 0;
 out:
```
