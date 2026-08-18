# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2603_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2603_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 1314-1354 of the vulnerable file.

 *	bio_map_user_iov - map user iovec into bio
 *	@q:		the struct request_queue for the bio
 *	@iter:		iovec iterator
 *	@gfp_mask:	memory allocation flags
 *
 *	Map the user space address into a bio suitable for io to a block
 *	device. Returns an error pointer in case of error.
 */
struct bio *bio_map_user_iov(struct request_queue *q,
			     const struct iov_iter *iter,
			     gfp_t gfp_mask)
{
	int j;
	int nr_pages = 0;
	struct page **pages;
	struct bio *bio;
	int cur_page = 0;
	int ret, offset;
	struct iov_iter i;
	struct iovec iov;

	iov_for_each(iov, i, *iter) {
		unsigned long uaddr = (unsigned long) iov.iov_base;
		unsigned long len = iov.iov_len;
		unsigned long end = (uaddr + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
		unsigned long start = uaddr >> PAGE_SHIFT;

		/*
		 * Overflow, abort
		 */
		if (end < start)
			return ERR_PTR(-EINVAL);

		nr_pages += end - start;
		/*
		 * buffer must be aligned to at least logical block size for now
		 */
		if (uaddr & queue_dma_alignment(q))
			return ERR_PTR(-EINVAL);
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1331,6 +1331,7 @@
 	int ret, offset;
 	struct iov_iter i;
 	struct iovec iov;
+	struct bio_vec *bvec;
 
 	iov_for_each(iov, i, *iter) {
 		unsigned long uaddr = (unsigned long) iov.iov_base;
@@ -1375,7 +1376,12 @@
 		ret = get_user_pages_fast(uaddr, local_nr_pages,
 				(iter->type & WRITE) != WRITE,
 				&pages[cur_page]);
-		if (ret < local_nr_pages) {
+		if (unlikely(ret < local_nr_pages)) {
+			for (j = cur_page; j < page_limit; j++) {
+				if (!pages[j])
+					break;
+				put_page(pages[j]);
+			}
 			ret = -EFAULT;
 			goto out_unmap;
 		}
@@ -1431,10 +1437,8 @@
 	return bio;
 
  out_unmap:
-	for (j = 0; j < nr_pages; j++) {
-		if (!pages[j])
-			break;
-		put_page(pages[j]);
+	bio_for_each_segment_all(bvec, bio, j) {
+		put_page(bvec->bv_page);
 	}
  out:
 	kfree(pages);
```
