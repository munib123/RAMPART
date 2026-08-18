# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2015_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2015_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 763-807 of the vulnerable file.

	return sys_recv(fd, buf, len, flags | MSG_CMSG_COMPAT);
}

asmlinkage long compat_sys_recvfrom(int fd, void __user *buf, size_t len,
				    unsigned int flags, struct sockaddr __user *addr,
				    int __user *addrlen)
{
	return sys_recvfrom(fd, buf, len, flags | MSG_CMSG_COMPAT, addr, addrlen);
}

asmlinkage long compat_sys_recvmmsg(int fd, struct compat_mmsghdr __user *mmsg,
				    unsigned int vlen, unsigned int flags,
				    struct compat_timespec __user *timeout)
{
	int datagrams;
	struct timespec ktspec;

	if (flags & MSG_CMSG_COMPAT)
		return -EINVAL;

	if (COMPAT_USE_64BIT_TIME)
		return __sys_recvmmsg(fd, (struct mmsghdr __user *)mmsg, vlen,
				      flags | MSG_CMSG_COMPAT,
				      (struct timespec *) timeout);

	if (timeout == NULL)
		return __sys_recvmmsg(fd, (struct mmsghdr __user *)mmsg, vlen,
				      flags | MSG_CMSG_COMPAT, NULL);

	if (get_compat_timespec(&ktspec, timeout))
		return -EFAULT;

	datagrams = __sys_recvmmsg(fd, (struct mmsghdr __user *)mmsg, vlen,
				   flags | MSG_CMSG_COMPAT, &ktspec);
	if (datagrams > 0 && put_compat_timespec(&ktspec, timeout))
		datagrams = -EFAULT;

	return datagrams;
}

asmlinkage long compat_sys_socketcall(int call, u32 __user *args)
{
	int ret;
	u32 a[6];
	u32 a0, a1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -780,21 +780,16 @@
 	if (flags & MSG_CMSG_COMPAT)
 		return -EINVAL;
 
-	if (COMPAT_USE_64BIT_TIME)
-		return __sys_recvmmsg(fd, (struct mmsghdr __user *)mmsg, vlen,
-				      flags | MSG_CMSG_COMPAT,
-				      (struct timespec *) timeout);
-
 	if (timeout == NULL)
 		return __sys_recvmmsg(fd, (struct mmsghdr __user *)mmsg, vlen,
 				      flags | MSG_CMSG_COMPAT, NULL);
 
-	if (get_compat_timespec(&ktspec, timeout))
+	if (compat_get_timespec(&ktspec, timeout))
 		return -EFAULT;
 
 	datagrams = __sys_recvmmsg(fd, (struct mmsghdr __user *)mmsg, vlen,
 				   flags | MSG_CMSG_COMPAT, &ktspec);
-	if (datagrams > 0 && put_compat_timespec(&ktspec, timeout))
+	if (datagrams > 0 && compat_put_timespec(&ktspec, timeout))
 		datagrams = -EFAULT;
 
 	return datagrams;
```
