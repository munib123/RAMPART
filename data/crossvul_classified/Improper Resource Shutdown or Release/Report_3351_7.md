# CrossVul Fix Pair: Improper Resource Shutdown or Release in c
**Pair ID:** 3351_7
**Vulnerability Class:** Improper Resource Shutdown or Release
**CWE:** CWE-404
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3351_7`)

## Vulnerability Information & PoC

## Description
Improper Resource Shutdown or Release - When a resource is created or allocated, the developer is responsible for properly releasing the resource as well as accounting for all potential paths of expiration or invalidation, such as a set ...

## Vulnerable Code
```c
Lines 240-280 of the vulnerable file.

	 || !(p = decode_filename(p, &args->name, &args->len)))
		return 0;

	return xdr_argsize_check(rqstp, p);
}

int
nfssvc_decode_readargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_readargs *args)
{
	unsigned int len;
	int v;
	p = decode_fh(p, &args->fh);
	if (!p)
		return 0;

	args->offset    = ntohl(*p++);
	len = args->count     = ntohl(*p++);
	p++; /* totalcount - unused */

	len = min_t(unsigned int, len, NFSSVC_MAXBLKSIZE_V2);

	/* set up somewhere to store response.
	 * We take pages, put them on reslist and include in iovec
	 */
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
nfssvc_decode_writeargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_writeargs *args)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -257,6 +257,9 @@
 	len = args->count     = ntohl(*p++);
 	p++; /* totalcount - unused */
 
+	if (!xdr_argsize_check(rqstp, p))
+		return 0;
+
 	len = min_t(unsigned int, len, NFSSVC_MAXBLKSIZE_V2);
 
 	/* set up somewhere to store response.
@@ -272,7 +275,7 @@
 		v++;
 	}
 	args->vlen = v;
-	return xdr_argsize_check(rqstp, p);
+	return 1;
 }
 
 int
@@ -362,9 +365,11 @@
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
@@ -402,9 +407,11 @@
 	args->cookie = ntohl(*p++);
 	args->count  = ntohl(*p++);
 	args->count  = min_t(u32, args->count, PAGE_SIZE);
+	if (!xdr_argsize_check(rqstp, p))
+		return 0;
 	args->buffer = page_address(*(rqstp->rq_next_page++));
 
-	return xdr_argsize_check(rqstp, p);
+	return 1;
 }
 
 /*
```
