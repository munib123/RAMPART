# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4857_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4857_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 5485-5526 of the vulnerable file.

		return(0);
	}
}

/*
 * Replace a single strip (tile) of uncompressed data by multiple strips
 * (tiles), each approximately STRIP_SIZE_DEFAULT bytes. This is useful for
 * dealing with large images or for dealing with machines with a limited
 * amount memory.
 */
static void
ChopUpSingleUncompressedStrip(TIFF* tif)
{
	register TIFFDirectory *td = &tif->tif_dir;
	uint64 bytecount;
	uint64 offset;
	uint32 rowblock;
	uint64 rowblockbytes;
	uint64 stripbytes;
	uint32 strip;
	uint64 nstrips64;
	uint32 nstrips32;
	uint32 rowsperstrip;
	uint64* newcounts;
	uint64* newoffsets;

	bytecount = td->td_stripbytecount[0];
	offset = td->td_stripoffset[0];
	assert(td->td_planarconfig == PLANARCONFIG_CONTIG);
	if ((td->td_photometric == PHOTOMETRIC_YCBCR)&&
	    (!isUpSampled(tif)))
		rowblock = td->td_ycbcrsubsampling[1];
	else
		rowblock = 1;
	rowblockbytes = TIFFVTileSize64(tif, rowblock);
	/*
	 * Make the rows hold at least one scanline, but fill specified amount
	 * of data if possible.
	 */
	if (rowblockbytes > STRIP_SIZE_DEFAULT) {
		stripbytes = rowblockbytes;
		rowsperstrip = rowblock;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5502,8 +5502,7 @@
 	uint64 rowblockbytes;
 	uint64 stripbytes;
 	uint32 strip;
-	uint64 nstrips64;
-	uint32 nstrips32;
+	uint32 nstrips;
 	uint32 rowsperstrip;
 	uint64* newcounts;
 	uint64* newoffsets;
@@ -5534,18 +5533,17 @@
 	    return;
 
 	/*
-	 * never increase the number of strips in an image
+	 * never increase the number of rows per strip
 	 */
 	if (rowsperstrip >= td->td_rowsperstrip)
 		return;
-	nstrips64 = TIFFhowmany_64(bytecount, stripbytes);
-	if ((nstrips64==0)||(nstrips64>0xFFFFFFFF)) /* something is wonky, do nothing. */
-	    return;
-	nstrips32 = (uint32)nstrips64;
-
-	newcounts = (uint64*) _TIFFCheckMalloc(tif, nstrips32, sizeof (uint64),
+        nstrips = TIFFhowmany_32(td->td_imagelength, rowsperstrip);
+        if( nstrips == 0 )
+            return;
+
+	newcounts = (uint64*) _TIFFCheckMalloc(tif, nstrips, sizeof (uint64),
 				"for chopped \"StripByteCounts\" array");
-	newoffsets = (uint64*) _TIFFCheckMalloc(tif, nstrips32, sizeof (uint64),
+	newoffsets = (uint64*) _TIFFCheckMalloc(tif, nstrips, sizeof (uint64),
 				"for chopped \"StripOffsets\" array");
 	if (newcounts == NULL || newoffsets == NULL) {
 		/*
@@ -5562,18 +5560,18 @@
 	 * Fill the strip information arrays with new bytecounts and offsets
 	 * that reflect the broken-up format.
 	 */
-	for (strip = 0; strip < nstrips32; strip++) {
+	for (strip = 0; strip < nstrips; strip++) {
 		if (stripbytes > bytecount)
 			stripbytes = bytecount;
 		newcounts[strip] = stripbytes;
-		newoffsets[strip] = offset;
+		newoffsets[strip] = stripbytes ? offset : 0;
 		offset += stripbytes;
 		bytecount -= stripbytes;
 	}
 	/*
 	 * Replace old single strip info with multi-strip info.
 	 */
-	td->td_stripsperimage = td->td_nstrips = nstrips32;
+	td->td_stripsperimage = td->td_nstrips = nstrips;
 	TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, rowsperstrip);
 
 	_TIFFfree(td->td_stripbytecount);
```
