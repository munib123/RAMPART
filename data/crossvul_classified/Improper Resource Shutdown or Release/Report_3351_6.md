# CrossVul Fix Pair: Improper Resource Shutdown or Release in c
**Pair ID:** 3351_6
**Vulnerability Class:** Improper Resource Shutdown or Release
**CWE:** CWE-404
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3351_6`)

## Vulnerability Information & PoC

## Description
Improper Resource Shutdown or Release - When a resource is created or allocated, the developer is responsible for properly releasing the resource as well as accounting for all potential paths of expiration or invalidation, such as a set ...

## Vulnerable Code
```c
Lines 2814-2856 of the vulnerable file.

	if (bmval1 & FATTR4_WORD1_FS_LAYOUT_TYPES) {
		status = nfsd4_encode_layout_types(xdr, exp->ex_layout_types);
		if (status)
			goto out;
	}

	if (bmval2 & FATTR4_WORD2_LAYOUT_TYPES) {
		status = nfsd4_encode_layout_types(xdr, exp->ex_layout_types);
		if (status)
			goto out;
	}

	if (bmval2 & FATTR4_WORD2_LAYOUT_BLKSIZE) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(stat.blksize);
	}
#endif /* CONFIG_NFSD_PNFS */
	if (bmval2 & FATTR4_WORD2_SUPPATTR_EXCLCREAT) {
		status = nfsd4_encode_bitmap(xdr, NFSD_SUPPATTR_EXCLCREAT_WORD0,
						  NFSD_SUPPATTR_EXCLCREAT_WORD1,
						  NFSD_SUPPATTR_EXCLCREAT_WORD2);
		if (status)
			goto out;
	}

	if (bmval2 & FATTR4_WORD2_SECURITY_LABEL) {
		status = nfsd4_encode_security_label(xdr, rqstp, context,
								contextlen);
		if (status)
			goto out;
	}

	attrlen = htonl(xdr->buf->len - attrlen_offset - 4);
	write_bytes_to_xdr_buf(xdr->buf, attrlen_offset, &attrlen, 4);
	status = nfs_ok;

out:
#ifdef CONFIG_NFSD_V4_SECURITY_LABEL
	if (context)
		security_release_secctx(context, contextlen);
#endif /* CONFIG_NFSD_V4_SECURITY_LABEL */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2831,9 +2831,14 @@
 	}
 #endif /* CONFIG_NFSD_PNFS */
 	if (bmval2 & FATTR4_WORD2_SUPPATTR_EXCLCREAT) {
-		status = nfsd4_encode_bitmap(xdr, NFSD_SUPPATTR_EXCLCREAT_WORD0,
-						  NFSD_SUPPATTR_EXCLCREAT_WORD1,
-						  NFSD_SUPPATTR_EXCLCREAT_WORD2);
+		u32 supp[3];
+
+		memcpy(supp, nfsd_suppattrs[minorversion], sizeof(supp));
+		supp[0] &= NFSD_SUPPATTR_EXCLCREAT_WORD0;
+		supp[1] &= NFSD_SUPPATTR_EXCLCREAT_WORD1;
+		supp[2] &= NFSD_SUPPATTR_EXCLCREAT_WORD2;
+
+		status = nfsd4_encode_bitmap(xdr, supp[0], supp[1], supp[2]);
 		if (status)
 			goto out;
 	}
@@ -4119,8 +4124,7 @@
 		struct nfsd4_getdeviceinfo *gdev)
 {
 	struct xdr_stream *xdr = &resp->xdr;
-	const struct nfsd4_layout_ops *ops =
-		nfsd4_layout_ops[gdev->gd_layout_type];
+	const struct nfsd4_layout_ops *ops;
 	u32 starting_len = xdr->buf->len, needed_len;
 	__be32 *p;
 
@@ -4137,6 +4141,7 @@
 
 	/* If maxcount is 0 then just update notifications */
 	if (gdev->gd_maxcount != 0) {
+		ops = nfsd4_layout_ops[gdev->gd_layout_type];
 		nfserr = ops->encode_getdeviceinfo(xdr, gdev);
 		if (nfserr) {
 			/*
@@ -4189,8 +4194,7 @@
 		struct nfsd4_layoutget *lgp)
 {
 	struct xdr_stream *xdr = &resp->xdr;
-	const struct nfsd4_layout_ops *ops =
-		nfsd4_layout_ops[lgp->lg_layout_type];
+	const struct nfsd4_layout_ops *ops;
 	__be32 *p;
 
 	dprintk("%s: err %d\n", __func__, nfserr);
@@ -4213,6 +4217,7 @@
 	*p++ = cpu_to_be32(lgp->lg_seg.iomode);
 	*p++ = cpu_to_be32(lgp->lg_layout_type);
 
+	ops = nfsd4_layout_ops[lgp->lg_layout_type];
 	nfserr = ops->encode_layoutget(xdr, lgp);
 out:
 	kfree(lgp->lg_content);
```
