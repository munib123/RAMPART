# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1806_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1806_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1032-1072 of the vulnerable file.

				     iov_iter_count(ii));

		bytes = min_t(size_t, bytes, fc->max_write - count);

 again:
		err = -EFAULT;
		if (iov_iter_fault_in_readable(ii, bytes))
			break;

		err = -ENOMEM;
		page = grab_cache_page_write_begin(mapping, index, 0);
		if (!page)
			break;

		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		tmp = iov_iter_copy_from_user_atomic(page, ii, offset, bytes);
		flush_dcache_page(page);

		if (!tmp) {
			unlock_page(page);
			page_cache_release(page);
			bytes = min(bytes, iov_iter_single_seg_count(ii));
			goto again;
		}

		err = 0;
		req->pages[req->num_pages] = page;
		req->page_descs[req->num_pages].length = tmp;
		req->num_pages++;

		iov_iter_advance(ii, tmp);
		count += tmp;
		pos += tmp;
		offset += tmp;
		if (offset == PAGE_CACHE_SIZE)
			offset = 0;

		if (!fc->big_writes)
			break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1049,6 +1049,7 @@
 		tmp = iov_iter_copy_from_user_atomic(page, ii, offset, bytes);
 		flush_dcache_page(page);
 
+		iov_iter_advance(ii, tmp);
 		if (!tmp) {
 			unlock_page(page);
 			page_cache_release(page);
@@ -1061,7 +1062,6 @@
 		req->page_descs[req->num_pages].length = tmp;
 		req->num_pages++;
 
-		iov_iter_advance(ii, tmp);
 		count += tmp;
 		pos += tmp;
 		offset += tmp;
```
