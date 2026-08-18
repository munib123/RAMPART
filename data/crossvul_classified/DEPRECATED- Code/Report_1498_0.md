# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 1498_0
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1498_0`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 125-184 of the vulnerable file.

	while (len > 0) {
		while (!iov->iov_len)
			iov++;
		copy = min_t(unsigned long, len, iov->iov_len);

		if (atomic) {
			if (__copy_from_user_inatomic(to, iov->iov_base, copy))
				return -EFAULT;
		} else {
			if (copy_from_user(to, iov->iov_base, copy))
				return -EFAULT;
		}
		to += copy;
		len -= copy;
		iov->iov_base += copy;
		iov->iov_len -= copy;
	}
	return 0;
}

static int
pipe_iov_copy_to_user(struct iovec *iov, const void *from, unsigned long len,
		      int atomic)
{
	unsigned long copy;

	while (len > 0) {
		while (!iov->iov_len)
			iov++;
		copy = min_t(unsigned long, len, iov->iov_len);

		if (atomic) {
			if (__copy_to_user_inatomic(iov->iov_base, from, copy))
				return -EFAULT;
		} else {
			if (copy_to_user(iov->iov_base, from, copy))
				return -EFAULT;
		}
		from += copy;
		len -= copy;
		iov->iov_base += copy;
		iov->iov_len -= copy;
	}
	return 0;
}

/*
 * Attempt to pre-fault in the user memory, so we can use atomic copies.
 * Returns the number of bytes not faulted in.
 */
static int iov_fault_in_pages_write(struct iovec *iov, unsigned long len)
{
	while (!iov->iov_len)
		iov++;

	while (len > 0) {
		unsigned long this_len;

		this_len = min_t(unsigned long, len, iov->iov_len);
		if (fault_in_pages_writeable(iov->iov_base, this_len))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -142,55 +142,6 @@
 	return 0;
 }
 
-static int
-pipe_iov_copy_to_user(struct iovec *iov, const void *from, unsigned long len,
-		      int atomic)
-{
-	unsigned long copy;
-
-	while (len > 0) {
-		while (!iov->iov_len)
-			iov++;
-		copy = min_t(unsigned long, len, iov->iov_len);
-
-		if (atomic) {
-			if (__copy_to_user_inatomic(iov->iov_base, from, copy))
-				return -EFAULT;
-		} else {
-			if (copy_to_user(iov->iov_base, from, copy))
-				return -EFAULT;
-		}
-		from += copy;
-		len -= copy;
-		iov->iov_base += copy;
-		iov->iov_len -= copy;
-	}
-	return 0;
-}
-
-/*
- * Attempt to pre-fault in the user memory, so we can use atomic copies.
- * Returns the number of bytes not faulted in.
- */
-static int iov_fault_in_pages_write(struct iovec *iov, unsigned long len)
-{
-	while (!iov->iov_len)
-		iov++;
-
-	while (len > 0) {
-		unsigned long this_len;
-
-		this_len = min_t(unsigned long, len, iov->iov_len);
-		if (fault_in_pages_writeable(iov->iov_base, this_len))
-			break;
-
-		len -= this_len;
-		iov++;
-	}
-
-	return len;
-}
-
 /*
  * Pre-fault in the user memory, so we can use atomic copies.
  */
@@ -329,11 +280,14 @@
 	ssize_t ret;
 	struct iovec *iov = (struct iovec *)_iov;
 	size_t total_len;
+	struct iov_iter iter;
 
 	total_len = iov_length(iov, nr_segs);
 	/* Null read succeeds. */
 	if (unlikely(total_len == 0))
 		return 0;
+
+	iov_iter_init(&iter, iov, nr_segs, total_len, 0);
 
 	do_wakeup = 0;
 	ret = 0;
@@ -344,9 +298,9 @@
 			int curbuf = pipe->curbuf;
 			struct pipe_buffer *buf = pipe->bufs + curbuf;
 			const struct pipe_buf_operations *ops = buf->ops;
-			void *addr;
 			size_t chars = buf->len;
-			int error, atomic;
+			size_t written;
+			int error;
 
 			if (chars > total_len)
 				chars = total_len;
@@ -358,27 +312,10 @@
 				break;
 			}
 
-			atomic = !iov_fault_in_pages_write(iov, chars);
-redo:
-			if (atomic)
-				addr = kmap_atomic(buf->page);
-			else
-				addr = kmap(buf->page);
-			error = pipe_iov_copy_to_user(iov, addr + buf->offset, chars, atomic);
-			if (atomic)
-				kunmap_atomic(addr);
-			else
-				kunmap(buf->page);
-			if (unlikely(error)) {
-				/*
-				 * Just retry with the slow path if we failed.
-				 */
-				if (atomic) {
-					atomic = 0;
-					goto redo;
-				}
+			written = copy_page_to_iter(buf->page, buf->offset, chars, &iter);
+			if (unlikely(written < chars)) {
 				if (!ret)
-					ret = error;
+					ret = -EFAULT;
 				break;
 			}
 			ret += chars;
```
