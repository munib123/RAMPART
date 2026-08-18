# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5241_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5241_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 246-286 of the vulnerable file.

	appendDynamic(dctx->dp, buf, size);

	if(dctx->dp->dataGood) {
		return size;
	} else {
		return -1;
	};
}

static void dynamicPutchar(struct gdIOCtx *ctx, int a)
{
	unsigned char b;
	dpIOCtxPtr dctx;

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
		if(remain <= 0) {
			/* 2.0.34: EOF is incorrect. We use 0 for
			 * errors and EOF, just like fileGetbuf,
			 * which is a simple fread() wrapper.
			 * TBB. Original bug report: Daniel Cowgill. */
			return 0; /* NOT EOF */
		}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -263,6 +263,7 @@
 	appendDynamic(dctx->dp, &b, 1);
 }
 
+/* returns the number of bytes actually read; 0 on EOF and error */
 static int dynamicGetbuf(gdIOCtxPtr ctx, void *buf, int len)
 {
 	int rlen, remain;
@@ -271,20 +272,24 @@
 
 	dctx = (dpIOCtxPtr) ctx;
 	dp = dctx->dp;
+
+	if (dp->pos < 0 || dp->pos >= dp->realSize) {
+		return 0;
+	}
 
 	remain = dp->logicalSize - dp->pos;
 	if(remain >= len) {
 		rlen = len;
 	} else {
 		if(remain <= 0) {
-			/* 2.0.34: EOF is incorrect. We use 0 for
-			 * errors and EOF, just like fileGetbuf,
-			 * which is a simple fread() wrapper.
-			 * TBB. Original bug report: Daniel Cowgill. */
-			return 0; /* NOT EOF */
+			return 0;
 		}
 
 		rlen = remain;
+	}
+
+	if (dp->pos + rlen > dp->realSize) {
+		rlen = dp->realSize - dp->pos;
 	}
 
 	memcpy(buf, (void *) ((char *)dp->data + dp->pos), rlen);
```
