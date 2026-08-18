# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4721_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4721_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1649-1689 of the vulnerable file.

		 * requests
		 */
		if (!is_compat)
			return -EINVAL;

		for (i = 0; i < count; i++) {
			dst[i].iov_base = compat_ptr(ciov[i].iov_base);
			dst[i].iov_len = ciov[i].iov_len;
		}
		return 0;
	}
#endif

	if (count * sizeof(struct iovec) != transferred)
		return -EIO;

	memcpy(dst, src, transferred);
	return 0;
}

/*
 * For ioctls, there is no generic way to determine how much memory
 * needs to be read and/or written.  Furthermore, ioctls are allowed
 * to dereference the passed pointer, so the parameter requires deep
 * copying but FUSE has no idea whatsoever about what to copy in or
 * out.
 *
 * This is solved by allowing FUSE server to retry ioctl with
 * necessary in/out iovecs.  Let's assume the ioctl implementation
 * needs to read in the following structure.
 *
 * struct a {
 *	char	*buf;
 *	size_t	buflen;
 * }
 *
 * On the first callout to FUSE server, inarg->in_size and
 * inarg->out_size will be NULL; then, the server completes the ioctl
 * with FUSE_IOCTL_RETRY set in out->flags, out->in_iovs set to 1 and
 * the actual iov array to
 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1663,6 +1663,20 @@
 		return -EIO;
 
 	memcpy(dst, src, transferred);
+	return 0;
+}
+
+/* Make sure iov_length() won't overflow */
+static int fuse_verify_ioctl_iov(struct iovec *iov, size_t count)
+{
+	size_t n;
+	u32 max = FUSE_MAX_PAGES_PER_REQ << PAGE_SHIFT;
+
+	for (n = 0; n < count; n++) {
+		if (iov->iov_len > (size_t) max)
+			return -ENOMEM;
+		max -= iov->iov_len;
+	}
 	return 0;
 }
 
@@ -1858,6 +1872,14 @@
 		in_iov = page_address(iov_page);
 		out_iov = in_iov + in_iovs;
 
+		err = fuse_verify_ioctl_iov(in_iov, in_iovs);
+		if (err)
+			goto out;
+
+		err = fuse_verify_ioctl_iov(out_iov, out_iovs);
+		if (err)
+			goto out;
+
 		goto retry;
 	}
 
```
