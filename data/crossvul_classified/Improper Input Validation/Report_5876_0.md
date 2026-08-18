# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5876_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5876_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1733-1773 of the vulnerable file.

		char __user *buf = i->iov->iov_base + i->iov_offset;
		left = __copy_from_user_nocache(kaddr + offset, buf, bytes);
		copied = bytes - left;
	} else {
		copied = __iovec_copy_from_user_inatomic(kaddr + offset,
						i->iov, i->iov_offset, bytes);
	}
	kunmap(page);
	return copied;
}
EXPORT_SYMBOL(iov_iter_copy_from_user);

static void __iov_iter_advance_iov(struct iov_iter *i, size_t bytes)
{
	if (likely(i->nr_segs == 1)) {
		i->iov_offset += bytes;
	} else {
		const struct iovec *iov = i->iov;
		size_t base = i->iov_offset;

		while (bytes) {
			int copy = min(bytes, iov->iov_len - base);

			bytes -= copy;
			base += copy;
			if (iov->iov_len == base) {
				iov++;
				base = 0;
			}
		}
		i->iov = iov;
		i->iov_offset = base;
	}
}

void iov_iter_advance(struct iov_iter *i, size_t bytes)
{
	BUG_ON(i->count < bytes);

	__iov_iter_advance_iov(i, bytes);
	i->count -= bytes;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1750,7 +1750,11 @@
 		const struct iovec *iov = i->iov;
 		size_t base = i->iov_offset;
 
-		while (bytes) {
+		/*
+		 * The !iov->iov_len check ensures we skip over unlikely
+		 * zero-length segments.
+		 */
+		while (bytes || !iov->iov_len) {
 			int copy = min(bytes, iov->iov_len - base);
 
 			bytes -= copy;
@@ -2268,6 +2272,7 @@
 
 		cond_resched();
 
+		iov_iter_advance(i, copied);
 		if (unlikely(copied == 0)) {
 			/*
 			 * If we were unable to copy any data at all, we must
@@ -2281,7 +2286,6 @@
 						iov_iter_single_seg_count(i));
 			goto again;
 		}
-		iov_iter_advance(i, copied);
 		pos += copied;
 		written += copied;
 
```
