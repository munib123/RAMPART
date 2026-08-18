# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2825_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2825_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1583-1623 of the vulnerable file.

		pid = find_get_pid(upid);

	wo.wo_type	= type;
	wo.wo_pid	= pid;
	wo.wo_flags	= options;
	wo.wo_info	= infop;
	wo.wo_rusage	= ru;
	ret = do_wait(&wo);

	put_pid(pid);
	return ret;
}

SYSCALL_DEFINE5(waitid, int, which, pid_t, upid, struct siginfo __user *,
		infop, int, options, struct rusage __user *, ru)
{
	struct rusage r;
	struct waitid_info info = {.status = 0};
	long err = kernel_waitid(which, upid, &info, options, ru ? &r : NULL);
	int signo = 0;
	if (err > 0) {
		signo = SIGCHLD;
		err = 0;
	}

	if (!err) {
		if (ru && copy_to_user(ru, &r, sizeof(struct rusage)))
			return -EFAULT;
	}
	if (!infop)
		return err;

	user_access_begin();
	unsafe_put_user(signo, &infop->si_signo, Efault);
	unsafe_put_user(0, &infop->si_errno, Efault);
	unsafe_put_user(info.cause, &infop->si_code, Efault);
	unsafe_put_user(info.pid, &infop->si_pid, Efault);
	unsafe_put_user(info.uid, &infop->si_uid, Efault);
	unsafe_put_user(info.status, &infop->si_status, Efault);
	user_access_end();
	return err;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1600,12 +1600,10 @@
 	struct waitid_info info = {.status = 0};
 	long err = kernel_waitid(which, upid, &info, options, ru ? &r : NULL);
 	int signo = 0;
+
 	if (err > 0) {
 		signo = SIGCHLD;
 		err = 0;
-	}
-
-	if (!err) {
 		if (ru && copy_to_user(ru, &r, sizeof(struct rusage)))
 			return -EFAULT;
 	}
@@ -1723,16 +1721,15 @@
 	if (err > 0) {
 		signo = SIGCHLD;
 		err = 0;
-	}
-
-	if (!err && uru) {
-		/* kernel_waitid() overwrites everything in ru */
-		if (COMPAT_USE_64BIT_TIME)
-			err = copy_to_user(uru, &ru, sizeof(ru));
-		else
-			err = put_compat_rusage(&ru, uru);
-		if (err)
-			return -EFAULT;
+		if (uru) {
+			/* kernel_waitid() overwrites everything in ru */
+			if (COMPAT_USE_64BIT_TIME)
+				err = copy_to_user(uru, &ru, sizeof(ru));
+			else
+				err = put_compat_rusage(&ru, uru);
+			if (err)
+				return -EFAULT;
+		}
 	}
 
 	if (!infop)
```
