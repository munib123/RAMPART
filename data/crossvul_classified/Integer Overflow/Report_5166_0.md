# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5166_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5166_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 121-161 of the vulnerable file.

	if ((*fmt != GD2_FMT_RAW) && (*fmt != GD2_FMT_COMPRESSED) && (*fmt != GD2_FMT_TRUECOLOR_RAW) && (*fmt != GD2_FMT_TRUECOLOR_COMPRESSED)) {
		GD2_DBG(php_gd_error("Bad data format: %d", *fmt));
		goto fail1;
	}

	/* # of chunks wide */
	if (gdGetWord(ncx, in) != 1) {
		goto fail1;
	}
	GD2_DBG(php_gd_error("%d Chunks Wide", *ncx));

	/* # of chunks high */
	if (gdGetWord(ncy, in) != 1) {
		goto fail1;
	}
	GD2_DBG(php_gd_error("%d Chunks vertically", *ncy));

	if (gd2_compressed(*fmt)) {
		nc = (*ncx) * (*ncy);
		GD2_DBG(php_gd_error("Reading %d chunk index entries", nc));
		sidx = sizeof(t_chunk_info) * nc;
		if (sidx <= 0) {
			goto fail1;
		}
		cidx = gdCalloc(sidx, 1);
		for (i = 0; i < nc; i++) {
			if (gdGetInt(&cidx[i].offset, in) != 1) {
				gdFree(cidx);
				goto fail1;
			}
			if (gdGetInt(&cidx[i].size, in) != 1) {
				gdFree(cidx);
				goto fail1;
			}
			if (cidx[i].offset < 0 || cidx[i].size < 0) {
				gdFree(cidx);
				goto fail1;
			}
		}
		*chunkIdx = cidx;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -138,11 +138,18 @@
 	if (gd2_compressed(*fmt)) {
 		nc = (*ncx) * (*ncy);
 		GD2_DBG(php_gd_error("Reading %d chunk index entries", nc));
+		if (overflow2(sidx, nc)) {
+			goto fail1;
+		}
 		sidx = sizeof(t_chunk_info) * nc;
 		if (sidx <= 0) {
 			goto fail1;
 		}
 		cidx = gdCalloc(sidx, 1);
+		if (cidx == NULL) {
+			goto fail1;
+		}
+
 		for (i = 0; i < nc; i++) {
 			if (gdGetInt(&cidx[i].offset, in) != 1) {
 				gdFree(cidx);
```
