# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3467_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3467_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 392-432 of the vulnerable file.

	return PAGE_SIZE;
}

SYSCALL_DEFINE0(getdtablesize)
{
	return sysctl_nr_open;
}

/*
 * For compatibility with OSF/1 only.  Use utsname(2) instead.
 */
SYSCALL_DEFINE2(osf_getdomainname, char __user *, name, int, namelen)
{
	unsigned len;
	int i;

	if (!access_ok(VERIFY_WRITE, name, namelen))
		return -EFAULT;

	len = namelen;
	if (namelen > 32)
		len = 32;

	down_read(&uts_sem);
	for (i = 0; i < len; ++i) {
		__put_user(utsname()->domainname[i], name + i);
		if (utsname()->domainname[i] == '\0')
			break;
	}
	up_read(&uts_sem);

	return 0;
}

/*
 * The following stuff should move into a header file should it ever
 * be labeled "officially supported."  Right now, there is just enough
 * support to avoid applications (such as tar) printing error
 * messages.  The attributes are not really implemented.
 */

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -409,7 +409,7 @@
 		return -EFAULT;
 
 	len = namelen;
-	if (namelen > 32)
+	if (len > 32)
 		len = 32;
 
 	down_read(&uts_sem);
@@ -594,7 +594,7 @@
 	down_read(&uts_sem);
 	res = sysinfo_table[offset];
 	len = strlen(res)+1;
-	if (len > count)
+	if ((unsigned long)len > (unsigned long)count)
 		len = count;
 	if (copy_to_user(buf, res, len))
 		err = -EFAULT;
@@ -649,7 +649,7 @@
 		return 1;
 
 	case GSI_GET_HWRPB:
-		if (nbytes < sizeof(*hwrpb))
+		if (nbytes > sizeof(*hwrpb))
 			return -EINVAL;
 		if (copy_to_user(buffer, hwrpb, nbytes) != 0)
 			return -EFAULT;
@@ -1008,6 +1008,7 @@
 {
 	struct rusage r;
 	long ret, err;
+	unsigned int status = 0;
 	mm_segment_t old_fs;
 
 	if (!ur)
@@ -1016,13 +1017,15 @@
 	old_fs = get_fs();
 		
 	set_fs (KERNEL_DS);
-	ret = sys_wait4(pid, ustatus, options, (struct rusage __user *) &r);
+	ret = sys_wait4(pid, (unsigned int __user *) &status, options,
+			(struct rusage __user *) &r);
 	set_fs (old_fs);
 
 	if (!access_ok(VERIFY_WRITE, ur, sizeof(*ur)))
 		return -EFAULT;
 
 	err = 0;
+	err |= put_user(status, ustatus);
 	err |= __put_user(r.ru_utime.tv_sec, &ur->ru_utime.tv_sec);
 	err |= __put_user(r.ru_utime.tv_usec, &ur->ru_utime.tv_usec);
 	err |= __put_user(r.ru_stime.tv_sec, &ur->ru_stime.tv_sec);
```
