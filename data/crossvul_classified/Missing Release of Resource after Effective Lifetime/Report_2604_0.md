# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2604_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2604_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 1366-1406 of the vulnerable file.


	iov_for_each(iov, i, *iter) {
		unsigned long uaddr = (unsigned long) iov.iov_base;
		unsigned long len = iov.iov_len;
		unsigned long end = (uaddr + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
		unsigned long start = uaddr >> PAGE_SHIFT;
		const int local_nr_pages = end - start;
		const int page_limit = cur_page + local_nr_pages;

		ret = get_user_pages_fast(uaddr, local_nr_pages,
				(iter->type & WRITE) != WRITE,
				&pages[cur_page]);
		if (ret < local_nr_pages) {
			ret = -EFAULT;
			goto out_unmap;
		}

		offset = offset_in_page(uaddr);
		for (j = cur_page; j < page_limit; j++) {
			unsigned int bytes = PAGE_SIZE - offset;

			if (len <= 0)
				break;
			
			if (bytes > len)
				bytes = len;

			/*
			 * sorry...
			 */
			if (bio_add_pc_page(q, bio, pages[j], bytes, offset) <
					    bytes)
				break;

			len -= bytes;
			offset = 0;
		}

		cur_page = j;
		/*
		 * release the pages we didn't map into the bio, if any
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1383,6 +1383,7 @@
 		offset = offset_in_page(uaddr);
 		for (j = cur_page; j < page_limit; j++) {
 			unsigned int bytes = PAGE_SIZE - offset;
+			unsigned short prev_bi_vcnt = bio->bi_vcnt;
 
 			if (len <= 0)
 				break;
@@ -1396,6 +1397,13 @@
 			if (bio_add_pc_page(q, bio, pages[j], bytes, offset) <
 					    bytes)
 				break;
+
+			/*
+			 * check if vector was merged with previous
+			 * drop page reference if needed
+			 */
+			if (bio->bi_vcnt == prev_bi_vcnt)
+				put_page(pages[j]);
 
 			len -= bytes;
 			offset = 0;
```
