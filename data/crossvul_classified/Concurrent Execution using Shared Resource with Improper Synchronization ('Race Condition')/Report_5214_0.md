# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 5214_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5214_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 573-613 of the vulnerable file.

	struct file_dedupe_range __user *argp = arg;
	struct file_dedupe_range *same = NULL;
	int ret;
	unsigned long size;
	u16 count;

	if (get_user(count, &argp->dest_count)) {
		ret = -EFAULT;
		goto out;
	}

	size = offsetof(struct file_dedupe_range __user, info[count]);

	same = memdup_user(argp, size);
	if (IS_ERR(same)) {
		ret = PTR_ERR(same);
		same = NULL;
		goto out;
	}

	ret = vfs_dedupe_file_range(file, same);
	if (ret)
		goto out;

	ret = copy_to_user(argp, same, size);
	if (ret)
		ret = -EFAULT;

out:
	kfree(same);
	return ret;
}

/*
 * When you add any new common ioctls to the switches above and below
 * please update compat_sys_ioctl() too.
 *
 * do_vfs_ioctl() is not for drivers and not intended to be EXPORT_SYMBOL()'d.
 * It's just a simple helper for sys_ioctl and compat_sys_ioctl.
 */
int do_vfs_ioctl(struct file *filp, unsigned int fd, unsigned int cmd,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -590,6 +590,7 @@
 		goto out;
 	}
 
+	same->dest_count = count;
 	ret = vfs_dedupe_file_range(file, same);
 	if (ret)
 		goto out;
```
