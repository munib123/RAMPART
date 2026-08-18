# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5357_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5357_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 259-299 of the vulnerable file.


	b = a;
	dctx = (dpIOCtxPtr) ctx;

	appendDynamic(dctx->dp, &b, 1);
}

static int dynamicGetbuf(gdIOCtxPtr ctx, void *buf, int len)
{
	int rlen, remain;
	dpIOCtxPtr dctx;
	dynamicPtr *dp;

	dctx = (dpIOCtxPtr) ctx;
	dp = dctx->dp;

	remain = dp->logicalSize - dp->pos;
	if(remain >= len) {
		rlen = len;
	} else {
		if(remain == 0) {
			/* 2.0.34: EOF is incorrect. We use 0 for
			 * errors and EOF, just like fileGetbuf,
			 * which is a simple fread() wrapper.
			 * TBB. Original bug report: Daniel Cowgill. */
			return 0; /* NOT EOF */
		}

		rlen = remain;
	}

	memcpy(buf, (void *) ((char *)dp->data + dp->pos), rlen);
	dp->pos += rlen;

	return rlen;
}

static int dynamicGetchar(gdIOCtxPtr ctx)
{
	unsigned char b;
	int rv;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -276,7 +276,7 @@
 	if(remain >= len) {
 		rlen = len;
 	} else {
-		if(remain == 0) {
+		if(remain <= 0) {
 			/* 2.0.34: EOF is incorrect. We use 0 for
 			 * errors and EOF, just like fileGetbuf,
 			 * which is a simple fread() wrapper.
```
