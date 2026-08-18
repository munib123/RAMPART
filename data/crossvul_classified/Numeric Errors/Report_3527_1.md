# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3527_1
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3527_1`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 2500-2540 of the vulnerable file.

	encode_putfh(xdr, args->fh, &hdr);
	encode_setattr(xdr, args, args->server, &hdr);
	encode_getfattr(xdr, args->bitmask, &hdr);
	encode_nops(&hdr);
}

/*
 * Encode a GETACL request
 */
static void nfs4_xdr_enc_getacl(struct rpc_rqst *req, struct xdr_stream *xdr,
				struct nfs_getaclargs *args)
{
	struct compound_hdr hdr = {
		.minorversion = nfs4_xdr_minorversion(&args->seq_args),
	};
	uint32_t replen;

	encode_compound_hdr(xdr, req, &hdr);
	encode_sequence(xdr, &args->seq_args, &hdr);
	encode_putfh(xdr, args->fh, &hdr);
	replen = hdr.replen + op_decode_hdr_maxsz + nfs4_fattr_bitmap_maxsz + 1;
	encode_getattr_two(xdr, FATTR4_WORD0_ACL, 0, &hdr);

	xdr_inline_pages(&req->rq_rcv_buf, replen << 2,
		args->acl_pages, args->acl_pgbase, args->acl_len);
	encode_nops(&hdr);
}

/*
 * Encode a WRITE request
 */
static void nfs4_xdr_enc_write(struct rpc_rqst *req, struct xdr_stream *xdr,
			       struct nfs_writeargs *args)
{
	struct compound_hdr hdr = {
		.minorversion = nfs4_xdr_minorversion(&args->seq_args),
	};

	encode_compound_hdr(xdr, req, &hdr);
	encode_sequence(xdr, &args->seq_args, &hdr);
	encode_putfh(xdr, args->fh, &hdr);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2517,11 +2517,13 @@
 	encode_compound_hdr(xdr, req, &hdr);
 	encode_sequence(xdr, &args->seq_args, &hdr);
 	encode_putfh(xdr, args->fh, &hdr);
-	replen = hdr.replen + op_decode_hdr_maxsz + nfs4_fattr_bitmap_maxsz + 1;
+	replen = hdr.replen + op_decode_hdr_maxsz + 1;
 	encode_getattr_two(xdr, FATTR4_WORD0_ACL, 0, &hdr);
 
 	xdr_inline_pages(&req->rq_rcv_buf, replen << 2,
 		args->acl_pages, args->acl_pgbase, args->acl_len);
+	xdr_set_scratch_buffer(xdr, page_address(args->acl_scratch), PAGE_SIZE);
+
 	encode_nops(&hdr);
 }
 
@@ -4957,17 +4959,18 @@
 }
 
 static int decode_getacl(struct xdr_stream *xdr, struct rpc_rqst *req,
-		size_t *acl_len)
-{
-	__be32 *savep;
+			 struct nfs_getaclres *res)
+{
+	__be32 *savep, *bm_p;
 	uint32_t attrlen,
 		 bitmap[3] = {0};
 	struct kvec *iov = req->rq_rcv_buf.head;
 	int status;
 
-	*acl_len = 0;
+	res->acl_len = 0;
 	if ((status = decode_op_hdr(xdr, OP_GETATTR)) != 0)
 		goto out;
+	bm_p = xdr->p;
 	if ((status = decode_attr_bitmap(xdr, bitmap)) != 0)
 		goto out;
 	if ((status = decode_attr_length(xdr, &attrlen, &savep)) != 0)
@@ -4979,18 +4982,30 @@
 		size_t hdrlen;
 		u32 recvd;
 
+		/* The bitmap (xdr len + bitmaps) and the attr xdr len words
+		 * are stored with the acl data to handle the problem of
+		 * variable length bitmaps.*/
+		xdr->p = bm_p;
+		res->acl_data_offset = be32_to_cpup(bm_p) + 2;
+		res->acl_data_offset <<= 2;
+
 		/* We ignore &savep and don't do consistency checks on
 		 * the attr length.  Let userspace figure it out.... */
 		hdrlen = (u8 *)xdr->p - (u8 *)iov->iov_base;
+		attrlen += res->acl_data_offset;
 		recvd = req->rq_rcv_buf.len - hdrlen;
 		if (attrlen > recvd) {
-			dprintk("NFS: server cheating in getattr"
-					" acl reply: attrlen %u > recvd %u\n",
+			if (res->acl_flags & NFS4_ACL_LEN_REQUEST) {
+				/* getxattr interface called with a NULL buf */
+				res->acl_len = attrlen;
+				goto out;
+			}
+			dprintk("NFS: acl reply: attrlen %u > recvd %u\n",
 					attrlen, recvd);
 			return -EINVAL;
 		}
 		xdr_read_pages(xdr, attrlen);
-		*acl_len = attrlen;
+		res->acl_len = attrlen;
 	} else
 		status = -EOPNOTSUPP;
 
@@ -6028,7 +6043,7 @@
 	status = decode_putfh(xdr);
 	if (status)
 		goto out;
-	status = decode_getacl(xdr, rqstp, &res->acl_len);
+	status = decode_getacl(xdr, rqstp, res);
 
 out:
 	return status;
```
