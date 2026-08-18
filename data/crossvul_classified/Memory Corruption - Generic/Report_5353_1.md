# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5353_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5353_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 357-397 of the vulnerable file.

	}

	/* If the split buffer was allocated on the heap, free this memory. */
	if (buf != splitbuf) {
		jas_free(buf);
	}

}

void jpc_qmfb_split_col(jpc_fix_t *a, int numrows, int stride,
  int parity)
{

	int bufsize = JPC_CEILDIVPOW2(numrows, 1);
	jpc_fix_t splitbuf[QMFB_SPLITBUFSIZE];
	jpc_fix_t *buf = splitbuf;
	register jpc_fix_t *srcptr;
	register jpc_fix_t *dstptr;
	register int n;
	register int m;
	int hstartcol;

	/* Get a buffer. */
	if (bufsize > QMFB_SPLITBUFSIZE) {
		if (!(buf = jas_alloc2(bufsize, sizeof(jpc_fix_t)))) {
			/* We have no choice but to commit suicide in this case. */
			abort();
		}
	}

	if (numrows >= 2) {
		hstartcol = (numrows + 1 - parity) >> 1;
		// ORIGINAL (WRONG): m = (parity) ? hstartcol : (numrows - hstartcol);
		m = numrows - hstartcol;

		/* Save the samples destined for the highpass channel. */
		n = m;
		dstptr = buf;
		srcptr = &a[(1 - parity) * stride];
		while (n-- > 0) {
			*dstptr = *srcptr;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -374,7 +374,7 @@
 	register jpc_fix_t *dstptr;
 	register int n;
 	register int m;
-	int hstartcol;
+	int hstartrow;
 
 	/* Get a buffer. */
 	if (bufsize > QMFB_SPLITBUFSIZE) {
@@ -385,9 +385,9 @@
 	}
 
 	if (numrows >= 2) {
-		hstartcol = (numrows + 1 - parity) >> 1;
-		// ORIGINAL (WRONG): m = (parity) ? hstartcol : (numrows - hstartcol);
-		m = numrows - hstartcol;
+		hstartrow = (numrows + 1 - parity) >> 1;
+		// ORIGINAL (WRONG): m = (parity) ? hstartrow : (numrows - hstartrow);
+		m = numrows - hstartrow;
 
 		/* Save the samples destined for the highpass channel. */
 		n = m;
@@ -408,7 +408,7 @@
 			srcptr += stride << 1;
 		}
 		/* Copy the saved samples into the highpass channel. */
-		dstptr = &a[hstartcol * stride];
+		dstptr = &a[hstartrow * stride];
 		srcptr = buf;
 		n = m;
 		while (n-- > 0) {
@@ -427,6 +427,90 @@
 
 void jpc_qmfb_split_colgrp(jpc_fix_t *a, int numrows, int stride,
   int parity)
+{
+
+	int bufsize = JPC_CEILDIVPOW2(numrows, 1);
+	jpc_fix_t splitbuf[QMFB_SPLITBUFSIZE * JPC_QMFB_COLGRPSIZE];
+	jpc_fix_t *buf = splitbuf;
+	jpc_fix_t *srcptr;
+	jpc_fix_t *dstptr;
+	register jpc_fix_t *srcptr2;
+	register jpc_fix_t *dstptr2;
+	register int n;
+	register int i;
+	int m;
+	int hstartrow;
+
+	/* Get a buffer. */
+	if (bufsize > QMFB_SPLITBUFSIZE) {
+		if (!(buf = jas_alloc3(bufsize, JPC_QMFB_COLGRPSIZE,
+		  sizeof(jpc_fix_t)))) {
+			/* We have no choice but to commit suicide in this case. */
+			abort();
+		}
+	}
+
+	if (numrows >= 2) {
+		hstartrow = (numrows + 1 - parity) >> 1;
+		// ORIGINAL (WRONG): m = (parity) ? hstartrow : (numrows - hstartrow);
+		m = numrows - hstartrow;
+
+		/* Save the samples destined for the highpass channel. */
+		n = m;
+		dstptr = buf;
+		srcptr = &a[(1 - parity) * stride];
+		while (n-- > 0) {
+			dstptr2 = dstptr;
+			srcptr2 = srcptr;
+			for (i = 0; i < JPC_QMFB_COLGRPSIZE; ++i) {
+				*dstptr2 = *srcptr2;
+				++dstptr2;
+				++srcptr2;
+			}
+			dstptr += JPC_QMFB_COLGRPSIZE;
+			srcptr += stride << 1;
+		}
+		/* Copy the appropriate samples into the lowpass channel. */
+		dstptr = &a[(1 - parity) * stride];
+		srcptr = &a[(2 - parity) * stride];
+		n = numrows - m - (!parity);
+		while (n-- > 0) {
+			dstptr2 = dstptr;
+			srcptr2 = srcptr;
+			for (i = 0; i < JPC_QMFB_COLGRPSIZE; ++i) {
+				*dstptr2 = *srcptr2;
+				++dstptr2;
+				++srcptr2;
+			}
+			dstptr += stride;
+			srcptr += stride << 1;
+		}
+		/* Copy the saved samples into the highpass channel. */
+		dstptr = &a[hstartrow * stride];
+		srcptr = buf;
+		n = m;
+		while (n-- > 0) {
+			dstptr2 = dstptr;
+			srcptr2 = srcptr;
+			for (i = 0; i < JPC_QMFB_COLGRPSIZE; ++i) {
+				*dstptr2 = *srcptr2;
+				++dstptr2;
+				++srcptr2;
+			}
+			dstptr += stride;
+			srcptr += JPC_QMFB_COLGRPSIZE;
+		}
+	}
+
+	/* If the split buffer was allocated on the heap, free this memory. */
+	if (buf != splitbuf) {
+		jas_free(buf);
+	}
+
+}
+
+void jpc_qmfb_split_colres(jpc_fix_t *a, int numrows, int numcols,
+  int stride, int parity)
 {
 
 	int bufsize = JPC_CEILDIVPOW2(numrows, 1);
@@ -443,90 +527,7 @@
 
 	/* Get a buffer. */
 	if (bufsize > QMFB_SPLITBUFSIZE) {
-		if (!(buf = jas_alloc2(bufsize, sizeof(jpc_fix_t)))) {
-			/* We have no choice but to commit suicide in this case. */
-			abort();
-		}
-	}
-
-	if (numrows >= 2) {
-		hstartcol = (numrows + 1 - parity) >> 1;
-		// ORIGINAL (WRONG): m = (parity) ? hstartcol : (numrows - hstartcol);
-		m = numrows - hstartcol;
-
-		/* Save the samples destined for the highpass channel. */
-		n = m;
-		dstptr = buf;
-		srcptr = &a[(1 - parity) * stride];
-		while (n-- > 0) {
-			dstptr2 = dstptr;
-			srcptr2 = srcptr;
-			for (i = 0; i < JPC_QMFB_COLGRPSIZE; ++i) {
-				*dstptr2 = *srcptr2;
-				++dstptr2;
-				++srcptr2;
-			}
-			dstptr += JPC_QMFB_COLGRPSIZE;
-			srcptr += stride << 1;
-		}
-		/* Copy the appropriate samples into the lowpass channel. */
-		dstptr = &a[(1 - parity) * stride];
-		srcptr = &a[(2 - parity) * stride];
-		n = numrows - m - (!parity);
-		while (n-- > 0) {
-			dstptr2 = dstptr;
-			srcptr2 = srcptr;
-			for (i = 0; i < JPC_QMFB_COLGRPSIZE; ++i) {
-				*dstptr2 = *srcptr2;
-				++dstptr2;
-				++srcptr2;
-			}
-			dstptr += stride;
-			srcptr += stride << 1;
-		}
-		/* Copy the saved samples into the highpass channel. */
-		dstptr = &a[hstartcol * stride];
-		srcptr = buf;
-		n = m;
-		while (n-- > 0) {
-			dstptr2 = dstptr;
-			srcptr2 = srcptr;
-			for (i = 0; i < JPC_QMFB_COLGRPSIZE; ++i) {
-				*dstptr2 = *srcptr2;
-				++dstptr2;
-				++srcptr2;
-			}
-			dstptr += stride;
-			srcptr += JPC_QMFB_COLGRPSIZE;
-		}
-	}
-
-	/* If the split buffer was allocated on the heap, free this memory. */
-	if (buf != splitbuf) {
-		jas_free(buf);
-	}
-
-}
-
-void jpc_qmfb_split_colres(jpc_fix_t *a, int numrows, int numcols,
-  int stride, int parity)
-{
-
-	int bufsize = JPC_CEILDIVPOW2(numrows, 1);
-	jpc_fix_t splitbuf[QMFB_SPLITBUFSIZE * JPC_QMFB_COLGRPSIZE];
-	jpc_fix_t *buf = splitbuf;
-	jpc_fix_t *srcptr;
-	jpc_fix_t *dstptr;
-	register jpc_fix_t *srcptr2;
-	register jpc_fix_t *dstptr2;
-	register int n;
-	register int i;
-	int m;
-	int hstartcol;
-
-	/* Get a buffer. */
-	if (bufsize > QMFB_SPLITBUFSIZE) {
-		if (!(buf = jas_alloc2(bufsize, sizeof(jpc_fix_t)))) {
+		if (!(buf = jas_alloc3(bufsize, numcols, sizeof(jpc_fix_t)))) {
 			/* We have no choice but to commit suicide in this case. */
 			abort();
 		}
@@ -721,7 +722,8 @@
 
 	/* Allocate memory for the join buffer from the heap. */
 	if (bufsize > QMFB_JOINBUFSIZE) {
-		if (!(buf = jas_alloc3(bufsize, JPC_QMFB_COLGRPSIZE, sizeof(jpc_fix_t)))) {
+		if (!(buf = jas_alloc3(bufsize, JPC_QMFB_COLGRPSIZE,
+		  sizeof(jpc_fix_t)))) {
 			/* We have no choice but to commit suicide. */
 			abort();
 		}
```
