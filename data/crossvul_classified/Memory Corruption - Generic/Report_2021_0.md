# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2021_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2021_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2372-2412 of the vulnerable file.

	server = tlink_tcon(wdata->cfile->tlink)->ses->server;

	do {
		if (wdata->cfile->invalidHandle) {
			rc = cifs_reopen_file(wdata->cfile, false);
			if (rc != 0)
				continue;
		}
		rc = server->ops->async_writev(wdata,
					       cifs_uncached_writedata_release);
	} while (rc == -EAGAIN);

	return rc;
}

static ssize_t
cifs_iovec_write(struct file *file, const struct iovec *iov,
		 unsigned long nr_segs, loff_t *poffset)
{
	unsigned long nr_pages, i;
	size_t copied, len, cur_len;
	ssize_t total_written = 0;
	loff_t offset;
	struct iov_iter it;
	struct cifsFileInfo *open_file;
	struct cifs_tcon *tcon;
	struct cifs_sb_info *cifs_sb;
	struct cifs_writedata *wdata, *tmp;
	struct list_head wdata_list;
	int rc;
	pid_t pid;

	len = iov_length(iov, nr_segs);
	if (!len)
		return 0;

	rc = generic_write_checks(file, poffset, &len, 0);
	if (rc)
		return rc;

	INIT_LIST_HEAD(&wdata_list);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2389,7 +2389,7 @@
 		 unsigned long nr_segs, loff_t *poffset)
 {
 	unsigned long nr_pages, i;
-	size_t copied, len, cur_len;
+	size_t bytes, copied, len, cur_len;
 	ssize_t total_written = 0;
 	loff_t offset;
 	struct iov_iter it;
@@ -2444,13 +2444,44 @@
 
 		save_len = cur_len;
 		for (i = 0; i < nr_pages; i++) {
-			copied = min_t(const size_t, cur_len, PAGE_SIZE);
+			bytes = min_t(const size_t, cur_len, PAGE_SIZE);
 			copied = iov_iter_copy_from_user(wdata->pages[i], &it,
-							 0, copied);
+							 0, bytes);
 			cur_len -= copied;
 			iov_iter_advance(&it, copied);
+			/*
+			 * If we didn't copy as much as we expected, then that
+			 * may mean we trod into an unmapped area. Stop copying
+			 * at that point. On the next pass through the big
+			 * loop, we'll likely end up getting a zero-length
+			 * write and bailing out of it.
+			 */
+			if (copied < bytes)
+				break;
 		}
 		cur_len = save_len - cur_len;
+
+		/*
+		 * If we have no data to send, then that probably means that
+		 * the copy above failed altogether. That's most likely because
+		 * the address in the iovec was bogus. Set the rc to -EFAULT,
+		 * free anything we allocated and bail out.
+		 */
+		if (!cur_len) {
+			for (i = 0; i < nr_pages; i++)
+				put_page(wdata->pages[i]);
+			kfree(wdata);
+			rc = -EFAULT;
+			break;
+		}
+
+		/*
+		 * i + 1 now represents the number of pages we actually used in
+		 * the copy phase above. Bring nr_pages down to that, and free
+		 * any pages that we didn't use.
+		 */
+		for ( ; nr_pages > i + 1; nr_pages--)
+			put_page(wdata->pages[nr_pages - 1]);
 
 		wdata->sync_mode = WB_SYNC_ALL;
 		wdata->nr_pages = nr_pages;
```
