# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 4799_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4799_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1146-1186 of the vulnerable file.

			}
		}
		if (TIFFWriteScanline(out, outbuf, row, 0) < 0) {
			TIFFError(TIFFFileName(out),
			    "Error, can't write scanline %lu",
			    (unsigned long) row);
			goto bad;
		}
	}
	if (inbuf) _TIFFfree(inbuf);
	if (outbuf) _TIFFfree(outbuf);
	return 1;
bad:
	if (inbuf) _TIFFfree(inbuf);
	if (outbuf) _TIFFfree(outbuf);
	return 0;
}

static void
cpStripToTile(uint8* out, uint8* in,
    uint32 rows, uint32 cols, int outskew, int inskew)
{
	while (rows-- > 0) {
		uint32 j = cols;
		while (j-- > 0)
			*out++ = *in++;
		out += outskew;
		in += inskew;
	}
}

static void
cpContigBufToSeparateBuf(uint8* out, uint8* in,
    uint32 rows, uint32 cols, int outskew, int inskew, tsample_t spp,
    int bytes_per_sample )
{
	while (rows-- > 0) {
		uint32 j = cols;
		while (j-- > 0)
		{
			int n = bytes_per_sample;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1163,7 +1163,7 @@
 
 static void
 cpStripToTile(uint8* out, uint8* in,
-    uint32 rows, uint32 cols, int outskew, int inskew)
+    uint32 rows, uint32 cols, int outskew, int64 inskew)
 {
 	while (rows-- > 0) {
 		uint32 j = cols;
@@ -1320,7 +1320,7 @@
 	tdata_t tilebuf;
 	uint32 imagew = TIFFScanlineSize(in);
 	uint32 tilew  = TIFFTileRowSize(in);
-	int iskew = imagew - tilew;
+	int64 iskew = (int64)imagew - (int64)tilew;
 	uint8* bufp = (uint8*) buf;
 	uint32 tw, tl;
 	uint32 row;
@@ -1348,7 +1348,7 @@
 				status = 0;
 				goto done;
 			}
-			if (colb + tilew > imagew) {
+			if (colb > iskew) {
 				uint32 width = imagew - colb;
 				uint32 oskew = tilew - width;
 				cpStripToTile(bufp + colb,
```
