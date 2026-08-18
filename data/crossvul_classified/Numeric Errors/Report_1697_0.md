# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 1697_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1697_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 1727-1769 of the vulnerable file.

	if (md) {
		if (!sg_res_in_use(sfp) && dxfer_len <= rsv_schp->bufflen)
			sg_link_reserve(sfp, srp, dxfer_len);
		else {
			res = sg_build_indirect(req_schp, sfp, dxfer_len);
			if (res)
				return res;
		}

		md->pages = req_schp->pages;
		md->page_order = req_schp->page_order;
		md->nr_entries = req_schp->k_use_sg;
		md->offset = 0;
		md->null_mapped = hp->dxferp ? 0 : 1;
		if (dxfer_dir == SG_DXFER_TO_FROM_DEV)
			md->from_user = 1;
		else
			md->from_user = 0;
	}

	if (unlikely(iov_count > MAX_UIOVEC))
		return -EINVAL;

	if (iov_count) {
		int size = sizeof(struct iovec) * iov_count;
		struct iovec *iov;
		struct iov_iter i;

		iov = memdup_user(hp->dxferp, size);
		if (IS_ERR(iov))
			return PTR_ERR(iov);

		iov_iter_init(&i, rw, iov, iov_count,
			      min_t(size_t, hp->dxfer_len,
				    iov_length(iov, iov_count)));

		res = blk_rq_map_user_iov(q, rq, md, &i, GFP_ATOMIC);
		kfree(iov);
	} else
		res = blk_rq_map_user(q, rq, md, hp->dxferp,
				      hp->dxfer_len, GFP_ATOMIC);

	if (!res) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1744,21 +1744,15 @@
 			md->from_user = 0;
 	}
 
-	if (unlikely(iov_count > MAX_UIOVEC))
-		return -EINVAL;
-
 	if (iov_count) {
-		int size = sizeof(struct iovec) * iov_count;
-		struct iovec *iov;
+		struct iovec *iov = NULL;
 		struct iov_iter i;
 
-		iov = memdup_user(hp->dxferp, size);
-		if (IS_ERR(iov))
-			return PTR_ERR(iov);
-
-		iov_iter_init(&i, rw, iov, iov_count,
-			      min_t(size_t, hp->dxfer_len,
-				    iov_length(iov, iov_count)));
+		res = import_iovec(rw, hp->dxferp, iov_count, 0, &iov, &i);
+		if (res < 0)
+			return res;
+
+		iov_iter_truncate(&i, hp->dxfer_len);
 
 		res = blk_rq_map_user_iov(q, rq, md, &i, GFP_ATOMIC);
 		kfree(iov);
```
