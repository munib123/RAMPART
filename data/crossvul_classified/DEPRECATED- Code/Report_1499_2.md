# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 1499_2
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1499_2`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 64-104 of the vulnerable file.

	bytes -= copy;
	while (unlikely(!left && bytes)) {
		iov++;
		buf = iov->iov_base;
		copy = min(bytes, iov->iov_len);
		left = __copy_to_user(buf, from, copy);
		copy -= left;
		skip = copy;
		from += copy;
		bytes -= copy;
	}
	kunmap(page);
done:
	i->count -= wanted - bytes;
	i->nr_segs -= iov - i->iov;
	i->iov = iov;
	i->iov_offset = skip;
	return wanted - bytes;
}
EXPORT_SYMBOL(copy_page_to_iter);

static size_t __iovec_copy_from_user_inatomic(char *vaddr,
			const struct iovec *iov, size_t base, size_t bytes)
{
	size_t copied = 0, left = 0;

	while (bytes) {
		char __user *buf = iov->iov_base + base;
		int copy = min(bytes, iov->iov_len - base);

		base = 0;
		left = __copy_from_user_inatomic(vaddr, buf, copy);
		copied += copy;
		bytes -= copy;
		vaddr += copy;
		iov++;

		if (unlikely(left))
			break;
	}
	return copied - left;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,6 +82,84 @@
 }
 EXPORT_SYMBOL(copy_page_to_iter);
 
+size_t copy_page_from_iter(struct page *page, size_t offset, size_t bytes,
+			 struct iov_iter *i)
+{
+	size_t skip, copy, left, wanted;
+	const struct iovec *iov;
+	char __user *buf;
+	void *kaddr, *to;
+
+	if (unlikely(bytes > i->count))
+		bytes = i->count;
+
+	if (unlikely(!bytes))
+		return 0;
+
+	wanted = bytes;
+	iov = i->iov;
+	skip = i->iov_offset;
+	buf = iov->iov_base + skip;
+	copy = min(bytes, iov->iov_len - skip);
+
+	if (!fault_in_pages_readable(buf, copy)) {
+		kaddr = kmap_atomic(page);
+		to = kaddr + offset;
+
+		/* first chunk, usually the only one */
+		left = __copy_from_user_inatomic(to, buf, copy);
+		copy -= left;
+		skip += copy;
+		to += copy;
+		bytes -= copy;
+
+		while (unlikely(!left && bytes)) {
+			iov++;
+			buf = iov->iov_base;
+			copy = min(bytes, iov->iov_len);
+			left = __copy_from_user_inatomic(to, buf, copy);
+			copy -= left;
+			skip = copy;
+			to += copy;
+			bytes -= copy;
+		}
+		if (likely(!bytes)) {
+			kunmap_atomic(kaddr);
+			goto done;
+		}
+		offset = to - kaddr;
+		buf += copy;
+		kunmap_atomic(kaddr);
+		copy = min(bytes, iov->iov_len - skip);
+	}
+	/* Too bad - revert to non-atomic kmap */
+	kaddr = kmap(page);
+	to = kaddr + offset;
+	left = __copy_from_user(to, buf, copy);
+	copy -= left;
+	skip += copy;
+	to += copy;
+	bytes -= copy;
+	while (unlikely(!left && bytes)) {
+		iov++;
+		buf = iov->iov_base;
+		copy = min(bytes, iov->iov_len);
+		left = __copy_from_user(to, buf, copy);
+		copy -= left;
+		skip = copy;
+		to += copy;
+		bytes -= copy;
+	}
+	kunmap(page);
+done:
+	i->count -= wanted - bytes;
+	i->nr_segs -= iov - i->iov;
+	i->iov = iov;
+	i->iov_offset = skip;
+	return wanted - bytes;
+}
+EXPORT_SYMBOL(copy_page_from_iter);
+
 static size_t __iovec_copy_from_user_inatomic(char *vaddr,
 			const struct iovec *iov, size_t base, size_t bytes)
 {
```
