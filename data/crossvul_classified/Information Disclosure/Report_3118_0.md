# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 3118_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3118_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 713-753 of the vulnerable file.

		struct iov_iter *i, unsigned long offset, size_t bytes)
{
	char *kaddr = kmap_atomic(page), *p = kaddr + offset;
	if (unlikely(i->type & ITER_PIPE)) {
		kunmap_atomic(kaddr);
		WARN_ON(1);
		return 0;
	}
	iterate_all_kinds(i, bytes, v,
		__copy_from_user_inatomic((p += v.iov_len) - v.iov_len,
					  v.iov_base, v.iov_len),
		memcpy_from_page((p += v.bv_len) - v.bv_len, v.bv_page,
				 v.bv_offset, v.bv_len),
		memcpy((p += v.iov_len) - v.iov_len, v.iov_base, v.iov_len)
	)
	kunmap_atomic(kaddr);
	return bytes;
}
EXPORT_SYMBOL(iov_iter_copy_from_user_atomic);

static void pipe_advance(struct iov_iter *i, size_t size)
{
	struct pipe_inode_info *pipe = i->pipe;
	struct pipe_buffer *buf;
	int idx = i->idx;
	size_t off = i->iov_offset, orig_sz;
	
	if (unlikely(i->count < size))
		size = i->count;
	orig_sz = size;

	if (size) {
		if (off) /* make it relative to the beginning of buffer */
			size += off - pipe->bufs[idx].offset;
		while (1) {
			buf = &pipe->bufs[idx];
			if (size <= buf->len)
				break;
			size -= buf->len;
			idx = next_idx(idx, pipe);
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -730,43 +730,50 @@
 }
 EXPORT_SYMBOL(iov_iter_copy_from_user_atomic);
 
-static void pipe_advance(struct iov_iter *i, size_t size)
+static inline void pipe_truncate(struct iov_iter *i)
 {
 	struct pipe_inode_info *pipe = i->pipe;
-	struct pipe_buffer *buf;
-	int idx = i->idx;
-	size_t off = i->iov_offset, orig_sz;
-	
-	if (unlikely(i->count < size))
-		size = i->count;
-	orig_sz = size;
-
-	if (size) {
-		if (off) /* make it relative to the beginning of buffer */
-			size += off - pipe->bufs[idx].offset;
-		while (1) {
-			buf = &pipe->bufs[idx];
-			if (size <= buf->len)
-				break;
-			size -= buf->len;
+	if (pipe->nrbufs) {
+		size_t off = i->iov_offset;
+		int idx = i->idx;
+		int nrbufs = (idx - pipe->curbuf) & (pipe->buffers - 1);
+		if (off) {
+			pipe->bufs[idx].len = off - pipe->bufs[idx].offset;
 			idx = next_idx(idx, pipe);
+			nrbufs++;
 		}
-		buf->len = size;
-		i->idx = idx;
-		off = i->iov_offset = buf->offset + size;
-	}
-	if (off)
-		idx = next_idx(idx, pipe);
-	if (pipe->nrbufs) {
-		int unused = (pipe->curbuf + pipe->nrbufs) & (pipe->buffers - 1);
-		/* [curbuf,unused) is in use.  Free [idx,unused) */
-		while (idx != unused) {
+		while (pipe->nrbufs > nrbufs) {
 			pipe_buf_release(pipe, &pipe->bufs[idx]);
 			idx = next_idx(idx, pipe);
 			pipe->nrbufs--;
 		}
 	}
-	i->count -= orig_sz;
+}
+
+static void pipe_advance(struct iov_iter *i, size_t size)
+{
+	struct pipe_inode_info *pipe = i->pipe;
+	if (unlikely(i->count < size))
+		size = i->count;
+	if (size) {
+		struct pipe_buffer *buf;
+		size_t off = i->iov_offset, left = size;
+		int idx = i->idx;
+		if (off) /* make it relative to the beginning of buffer */
+			left += off - pipe->bufs[idx].offset;
+		while (1) {
+			buf = &pipe->bufs[idx];
+			if (left <= buf->len)
+				break;
+			left -= buf->len;
+			idx = next_idx(idx, pipe);
+		}
+		i->idx = idx;
+		i->iov_offset = buf->offset + left;
+	}
+	i->count -= size;
+	/* ... and discard everything past that point */
+	pipe_truncate(i);
 }
 
 void iov_iter_advance(struct iov_iter *i, size_t size)
@@ -826,6 +833,7 @@
 			size_t count)
 {
 	BUG_ON(direction != ITER_PIPE);
+	WARN_ON(pipe->nrbufs == pipe->buffers);
 	i->type = direction;
 	i->pipe = pipe;
 	i->idx = (pipe->curbuf + pipe->nrbufs) & (pipe->buffers - 1);
```
