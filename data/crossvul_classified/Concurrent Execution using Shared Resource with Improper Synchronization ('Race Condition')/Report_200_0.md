# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 200_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `200_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 104-144 of the vulnerable file.

	size = max(hdr.size_in, hdr.size_out);
	if (_IOC_SIZE(req) && _IOC_SIZE(req) != size)
		return -EINVAL;
	if (size > SZ_16M)
		return -E2BIG;

	/*
	 * IOCTL_VMMDEV_REQUEST needs the buffer to be below 4G to avoid
	 * the need for a bounce-buffer and another copy later on.
	 */
	is_vmmdev_req = (req & ~IOCSIZE_MASK) == VBG_IOCTL_VMMDEV_REQUEST(0) ||
			 req == VBG_IOCTL_VMMDEV_REQUEST_BIG;

	if (is_vmmdev_req)
		buf = vbg_req_alloc(size, VBG_IOCTL_HDR_TYPE_DEFAULT);
	else
		buf = kmalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (copy_from_user(buf, (void *)arg, hdr.size_in)) {
		ret = -EFAULT;
		goto out;
	}
	if (hdr.size_in < size)
		memset(buf + hdr.size_in, 0, size -  hdr.size_in);

	ret = vbg_core_ioctl(session, req, buf);
	if (ret)
		goto out;

	returned_size = ((struct vbg_ioctl_hdr *)buf)->size_out;
	if (returned_size > size) {
		vbg_debug("%s: too much output data %zu > %zu\n",
			  __func__, returned_size, size);
		returned_size = size;
	}
	if (copy_to_user((void *)arg, buf, returned_size) != 0)
		ret = -EFAULT;

out:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -121,7 +121,9 @@
 	if (!buf)
 		return -ENOMEM;
 
-	if (copy_from_user(buf, (void *)arg, hdr.size_in)) {
+	*((struct vbg_ioctl_hdr *)buf) = hdr;
+	if (copy_from_user(buf + sizeof(hdr), (void *)arg + sizeof(hdr),
+			   hdr.size_in - sizeof(hdr))) {
 		ret = -EFAULT;
 		goto out;
 	}
```
