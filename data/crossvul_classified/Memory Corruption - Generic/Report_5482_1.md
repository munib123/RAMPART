# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 5482_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5482_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 1321-1361 of the vulnerable file.

	uint32 imagew = TIFFScanlineSize(in);
	uint32 tilew  = TIFFTileRowSize(in);
	int iskew = imagew - tilew;
	uint8* bufp = (uint8*) buf;
	uint32 tw, tl;
	uint32 row;

	(void) spp;
	tilebuf = _TIFFmalloc(tilesize);
	if (tilebuf == 0)
		return 0;
	_TIFFmemset(tilebuf, 0, tilesize);
	(void) TIFFGetField(in, TIFFTAG_TILEWIDTH, &tw);
	(void) TIFFGetField(in, TIFFTAG_TILELENGTH, &tl);
        
	for (row = 0; row < imagelength; row += tl) {
		uint32 nrow = (row+tl > imagelength) ? imagelength-row : tl;
		uint32 colb = 0;
		uint32 col;

		for (col = 0; col < imagewidth; col += tw) {
			if (TIFFReadTile(in, tilebuf, col, row, 0, 0) < 0
			    && !ignore) {
				TIFFError(TIFFFileName(in),
				    "Error, can't read tile at %lu %lu",
				    (unsigned long) col,
				    (unsigned long) row);
				status = 0;
				goto done;
			}
			if (colb + tilew > imagew) {
				uint32 width = imagew - colb;
				uint32 oskew = tilew - width;
				cpStripToTile(bufp + colb,
				    tilebuf, nrow, width,
				    oskew + iskew, oskew );
			} else
				cpStripToTile(bufp + colb,
				    tilebuf, nrow, tilew,
				    iskew, 0);
			colb += tilew;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1338,7 +1338,7 @@
 		uint32 colb = 0;
 		uint32 col;
 
-		for (col = 0; col < imagewidth; col += tw) {
+		for (col = 0; col < imagewidth && colb < imagew; col += tw) {
 			if (TIFFReadTile(in, tilebuf, col, row, 0, 0) < 0
 			    && !ignore) {
 				TIFFError(TIFFFileName(in),
@@ -1523,7 +1523,7 @@
 		uint32 colb = 0;
 		uint32 col;
 
-		for (col = 0; col < imagewidth; col += tw) {
+		for (col = 0; col < imagewidth && colb < imagew; col += tw) {
 			/*
 			 * Tile is clipped horizontally.  Calculate
 			 * visible portion and skewing factors.
```
