# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1861_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1861_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 176-216 of the vulnerable file.

				   struct oldabi_stat64  __user *statbuf,
				   int flag)
{
	struct kstat stat;
	int error;

	error = vfs_fstatat(dfd, filename, &stat, flag);
	if (error)
		return error;
	return cp_oldabi_stat64(&stat, statbuf);
}

struct oabi_flock64 {
	short	l_type;
	short	l_whence;
	loff_t	l_start;
	loff_t	l_len;
	pid_t	l_pid;
} __attribute__ ((packed,aligned(4)));

asmlinkage long sys_oabi_fcntl64(unsigned int fd, unsigned int cmd,
				 unsigned long arg)
{
	struct oabi_flock64 user;
	struct flock64 kernel;
	mm_segment_t fs = USER_DS; /* initialized to kill a warning */
	unsigned long local_arg = arg;
	int ret;

	switch (cmd) {
	case F_OFD_GETLK:
	case F_OFD_SETLK:
	case F_OFD_SETLKW:
	case F_GETLK64:
	case F_SETLK64:
	case F_SETLKW64:
		if (copy_from_user(&user, (struct oabi_flock64 __user *)arg,
				   sizeof(user)))
			return -EFAULT;
		kernel.l_type	= user.l_type;
		kernel.l_whence	= user.l_whence;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -193,15 +193,44 @@
 	pid_t	l_pid;
 } __attribute__ ((packed,aligned(4)));
 
+static long do_locks(unsigned int fd, unsigned int cmd,
+				 unsigned long arg)
+{
+	struct flock64 kernel;
+	struct oabi_flock64 user;
+	mm_segment_t fs;
+	long ret;
+
+	if (copy_from_user(&user, (struct oabi_flock64 __user *)arg,
+			   sizeof(user)))
+		return -EFAULT;
+	kernel.l_type	= user.l_type;
+	kernel.l_whence	= user.l_whence;
+	kernel.l_start	= user.l_start;
+	kernel.l_len	= user.l_len;
+	kernel.l_pid	= user.l_pid;
+
+	fs = get_fs();
+	set_fs(KERNEL_DS);
+	ret = sys_fcntl64(fd, cmd, (unsigned long)&kernel);
+	set_fs(fs);
+
+	if (!ret && (cmd == F_GETLK64 || cmd == F_OFD_GETLK)) {
+		user.l_type	= kernel.l_type;
+		user.l_whence	= kernel.l_whence;
+		user.l_start	= kernel.l_start;
+		user.l_len	= kernel.l_len;
+		user.l_pid	= kernel.l_pid;
+		if (copy_to_user((struct oabi_flock64 __user *)arg,
+				 &user, sizeof(user)))
+			ret = -EFAULT;
+	}
+	return ret;
+}
+
 asmlinkage long sys_oabi_fcntl64(unsigned int fd, unsigned int cmd,
 				 unsigned long arg)
 {
-	struct oabi_flock64 user;
-	struct flock64 kernel;
-	mm_segment_t fs = USER_DS; /* initialized to kill a warning */
-	unsigned long local_arg = arg;
-	int ret;
-
 	switch (cmd) {
 	case F_OFD_GETLK:
 	case F_OFD_SETLK:
@@ -209,39 +238,11 @@
 	case F_GETLK64:
 	case F_SETLK64:
 	case F_SETLKW64:
-		if (copy_from_user(&user, (struct oabi_flock64 __user *)arg,
-				   sizeof(user)))
-			return -EFAULT;
-		kernel.l_type	= user.l_type;
-		kernel.l_whence	= user.l_whence;
-		kernel.l_start	= user.l_start;
-		kernel.l_len	= user.l_len;
-		kernel.l_pid	= user.l_pid;
-		local_arg = (unsigned long)&kernel;
-		fs = get_fs();
-		set_fs(KERNEL_DS);
-	}
-
-	ret = sys_fcntl64(fd, cmd, local_arg);
-
-	switch (cmd) {
-	case F_GETLK64:
-		if (!ret) {
-			user.l_type	= kernel.l_type;
-			user.l_whence	= kernel.l_whence;
-			user.l_start	= kernel.l_start;
-			user.l_len	= kernel.l_len;
-			user.l_pid	= kernel.l_pid;
-			if (copy_to_user((struct oabi_flock64 __user *)arg,
-					 &user, sizeof(user)))
-				ret = -EFAULT;
-		}
-	case F_SETLK64:
-	case F_SETLKW64:
-		set_fs(fs);
-	}
-
-	return ret;
+		return do_locks(fd, cmd, arg);
+
+	default:
+		return sys_fcntl64(fd, cmd, arg);
+	}
 }
 
 struct oabi_epoll_event {
```
