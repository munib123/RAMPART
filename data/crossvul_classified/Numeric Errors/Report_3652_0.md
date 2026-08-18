# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3652_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3652_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 3695-3735 of the vulnerable file.

	resp_buf = page_address(pages[0]);

	dprintk("%s  buf %p buflen %zu npages %d args.acl_len %zu\n",
		__func__, buf, buflen, npages, args.acl_len);
	ret = nfs4_call_sync(NFS_SERVER(inode)->client, NFS_SERVER(inode),
			     &msg, &args.seq_args, &res.seq_res, 0);
	if (ret)
		goto out_free;

	acl_len = res.acl_len - res.acl_data_offset;
	if (acl_len > args.acl_len)
		nfs4_write_cached_acl(inode, NULL, acl_len);
	else
		nfs4_write_cached_acl(inode, resp_buf + res.acl_data_offset,
				      acl_len);
	if (buf) {
		ret = -ERANGE;
		if (acl_len > buflen)
			goto out_free;
		_copy_from_pages(buf, pages, res.acl_data_offset,
				res.acl_len);
	}
	ret = acl_len;
out_free:
	for (i = 0; i < npages; i++)
		if (pages[i])
			__free_page(pages[i]);
	if (res.acl_scratch)
		__free_page(res.acl_scratch);
	return ret;
}

static ssize_t nfs4_get_acl_uncached(struct inode *inode, void *buf, size_t buflen)
{
	struct nfs4_exception exception = { };
	ssize_t ret;
	do {
		ret = __nfs4_get_acl_uncached(inode, buf, buflen);
		if (ret >= 0)
			break;
		ret = nfs4_handle_exception(NFS_SERVER(inode), ret, &exception);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3712,7 +3712,7 @@
 		if (acl_len > buflen)
 			goto out_free;
 		_copy_from_pages(buf, pages, res.acl_data_offset,
-				res.acl_len);
+				acl_len);
 	}
 	ret = acl_len;
 out_free:
```
