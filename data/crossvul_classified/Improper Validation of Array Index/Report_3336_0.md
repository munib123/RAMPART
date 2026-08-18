# CrossVul Fix Pair: Improper Validation of Array Index in c
**Pair ID:** 3336_0
**Vulnerability Class:** Improper Validation of Array Index
**CWE:** CWE-129
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3336_0`)

## Vulnerability Information & PoC

## Description
Improper Validation of Array Index - The product uses untrusted input when calculating or using an array index, but the product does not validate or incorrectly validates the index to ensure the index references a valid position withi...

## Vulnerable Code
```c
Lines 4102-4143 of the vulnerable file.

		return nfserr;

	p = xdr_reserve_space(xdr, 4 + (4 * test_stateid->ts_num_ids));
	if (!p)
		return nfserr_resource;
	*p++ = htonl(test_stateid->ts_num_ids);

	list_for_each_entry_safe(stateid, next, &test_stateid->ts_stateid_list, ts_id_list) {
		*p++ = stateid->ts_id_status;
	}

	return nfserr;
}

#ifdef CONFIG_NFSD_PNFS
static __be32
nfsd4_encode_getdeviceinfo(struct nfsd4_compoundres *resp, __be32 nfserr,
		struct nfsd4_getdeviceinfo *gdev)
{
	struct xdr_stream *xdr = &resp->xdr;
	const struct nfsd4_layout_ops *ops =
		nfsd4_layout_ops[gdev->gd_layout_type];
	u32 starting_len = xdr->buf->len, needed_len;
	__be32 *p;

	dprintk("%s: err %d\n", __func__, be32_to_cpu(nfserr));
	if (nfserr)
		goto out;

	nfserr = nfserr_resource;
	p = xdr_reserve_space(xdr, 4);
	if (!p)
		goto out;

	*p++ = cpu_to_be32(gdev->gd_layout_type);

	/* If maxcount is 0 then just update notifications */
	if (gdev->gd_maxcount != 0) {
		nfserr = ops->encode_getdeviceinfo(xdr, gdev);
		if (nfserr) {
			/*
			 * We don't bother to burden the layout drivers with
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4119,8 +4119,7 @@
 		struct nfsd4_getdeviceinfo *gdev)
 {
 	struct xdr_stream *xdr = &resp->xdr;
-	const struct nfsd4_layout_ops *ops =
-		nfsd4_layout_ops[gdev->gd_layout_type];
+	const struct nfsd4_layout_ops *ops;
 	u32 starting_len = xdr->buf->len, needed_len;
 	__be32 *p;
 
@@ -4137,6 +4136,7 @@
 
 	/* If maxcount is 0 then just update notifications */
 	if (gdev->gd_maxcount != 0) {
+		ops = nfsd4_layout_ops[gdev->gd_layout_type];
 		nfserr = ops->encode_getdeviceinfo(xdr, gdev);
 		if (nfserr) {
 			/*
@@ -4189,8 +4189,7 @@
 		struct nfsd4_layoutget *lgp)
 {
 	struct xdr_stream *xdr = &resp->xdr;
-	const struct nfsd4_layout_ops *ops =
-		nfsd4_layout_ops[lgp->lg_layout_type];
+	const struct nfsd4_layout_ops *ops;
 	__be32 *p;
 
 	dprintk("%s: err %d\n", __func__, nfserr);
@@ -4213,6 +4212,7 @@
 	*p++ = cpu_to_be32(lgp->lg_seg.iomode);
 	*p++ = cpu_to_be32(lgp->lg_layout_type);
 
+	ops = nfsd4_layout_ops[lgp->lg_layout_type];
 	nfserr = ops->encode_layoutget(xdr, lgp);
 out:
 	kfree(lgp->lg_content);
```
