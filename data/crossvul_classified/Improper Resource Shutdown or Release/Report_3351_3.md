# CrossVul Fix Pair: Improper Resource Shutdown or Release in c
**Pair ID:** 3351_3
**Vulnerability Class:** Improper Resource Shutdown or Release
**CWE:** CWE-404
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3351_3`)

## Vulnerability Information & PoC

## Description
Improper Resource Shutdown or Release - When a resource is created or allocated, the developer is responsible for properly releasing the resource as well as accounting for all potential paths of expiration or invalidation, such as a set ...

## Vulnerable Code
```c
Lines 317-357 of the vulnerable file.

	p = decode_fh(p, &args->fh);
	if (!p)
		return 0;
	args->access = ntohl(*p++);

	return xdr_argsize_check(rqstp, p);
}

int
nfs3svc_decode_readargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_readargs *args)
{
	unsigned int len;
	int v;
	u32 max_blocksize = svc_max_payload(rqstp);

	p = decode_fh(p, &args->fh);
	if (!p)
		return 0;
	p = xdr_decode_hyper(p, &args->offset);

	args->count = ntohl(*p++);
	len = min(args->count, max_blocksize);

	/* set up the kvec */
	v=0;
	while (len > 0) {
		struct page *p = *(rqstp->rq_next_page++);

		rqstp->rq_vec[v].iov_base = page_address(p);
		rqstp->rq_vec[v].iov_len = min_t(unsigned int, len, PAGE_SIZE);
		len -= rqstp->rq_vec[v].iov_len;
		v++;
	}
	args->vlen = v;
	return xdr_argsize_check(rqstp, p);
}

int
nfs3svc_decode_writeargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_writeargs *args)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -334,8 +334,11 @@
 	if (!p)
 		return 0;
 	p = xdr_decode_hyper(p, &args->offset);
-
 	args->count = ntohl(*p++);
+
+	if (!xdr_argsize_check(rqstp, p))
+		return 0;
+
 	len = min(args->count, max_blocksize);
 
 	/* set up the kvec */
@@ -349,7 +352,7 @@
 		v++;
 	}
 	args->vlen = v;
-	return xdr_argsize_check(rqstp, p);
+	return 1;
 }
 
 int
@@ -541,9 +544,11 @@
 	p = decode_fh(p, &args->fh);
 	if (!p)
 		return 0;
+	if (!xdr_argsize_check(rqstp, p))
+		return 0;
 	args->buffer = page_address(*(rqstp->rq_next_page++));
 
-	return xdr_argsize_check(rqstp, p);
+	return 1;
 }
 
 int
@@ -569,10 +574,14 @@
 	args->verf   = p; p += 2;
 	args->dircount = ~0;
 	args->count  = ntohl(*p++);
+
+	if (!xdr_argsize_check(rqstp, p))
+		return 0;
+
 	args->count  = min_t(u32, args->count, PAGE_SIZE);
 	args->buffer = page_address(*(rqstp->rq_next_page++));
 
-	return xdr_argsize_check(rqstp, p);
+	return 1;
 }
 
 int
@@ -589,6 +598,9 @@
 	args->verf     = p; p += 2;
 	args->dircount = ntohl(*p++);
 	args->count    = ntohl(*p++);
+
+	if (!xdr_argsize_check(rqstp, p))
+		return 0;
 
 	len = args->count = min(args->count, max_blocksize);
 	while (len > 0) {
@@ -597,8 +609,7 @@
 			args->buffer = page_address(p);
 		len -= PAGE_SIZE;
 	}
-
-	return xdr_argsize_check(rqstp, p);
+	return 1;
 }
 
 int
```
