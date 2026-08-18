# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4857_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4857_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 45-93 of the vulnerable file.

	if (td->td_planarconfig == PLANARCONFIG_SEPARATE) {
		if (sample >= td->td_samplesperpixel) {
			TIFFErrorExt(tif->tif_clientdata, module,
			    "%lu: Sample out of range, max %lu",
			    (unsigned long) sample, (unsigned long) td->td_samplesperpixel);
			return (0);
		}
		strip += (uint32)sample*td->td_stripsperimage;
	}
	return (strip);
}

/*
 * Compute how many strips are in an image.
 */
uint32
TIFFNumberOfStrips(TIFF* tif)
{
	TIFFDirectory *td = &tif->tif_dir;
	uint32 nstrips;

    /* If the value was already computed and store in td_nstrips, then return it,
       since ChopUpSingleUncompressedStrip might have altered and resized the
       since the td_stripbytecount and td_stripoffset arrays to the new value
       after the initial affectation of td_nstrips = TIFFNumberOfStrips() in
       tif_dirread.c ~line 3612.
       See http://bugzilla.maptools.org/show_bug.cgi?id=2587 */
    if( td->td_nstrips )
        return td->td_nstrips;

	nstrips = (td->td_rowsperstrip == (uint32) -1 ? 1 :
	     TIFFhowmany_32(td->td_imagelength, td->td_rowsperstrip));
	if (td->td_planarconfig == PLANARCONFIG_SEPARATE)
		nstrips = _TIFFMultiply32(tif, nstrips, (uint32)td->td_samplesperpixel,
		    "TIFFNumberOfStrips");
	return (nstrips);
}

/*
 * Compute the # bytes in a variable height, row-aligned strip.
 */
uint64
TIFFVStripSize64(TIFF* tif, uint32 nrows)
{
	static const char module[] = "TIFFVStripSize64";
	TIFFDirectory *td = &tif->tif_dir;
	if (nrows==(uint32)(-1))
		nrows=td->td_imagelength;
	if ((td->td_planarconfig==PLANARCONFIG_CONTIG)&&
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -62,15 +62,6 @@
 {
 	TIFFDirectory *td = &tif->tif_dir;
 	uint32 nstrips;
-
-    /* If the value was already computed and store in td_nstrips, then return it,
-       since ChopUpSingleUncompressedStrip might have altered and resized the
-       since the td_stripbytecount and td_stripoffset arrays to the new value
-       after the initial affectation of td_nstrips = TIFFNumberOfStrips() in
-       tif_dirread.c ~line 3612.
-       See http://bugzilla.maptools.org/show_bug.cgi?id=2587 */
-    if( td->td_nstrips )
-        return td->td_nstrips;
 
 	nstrips = (td->td_rowsperstrip == (uint32) -1 ? 1 :
 	     TIFFhowmany_32(td->td_imagelength, td->td_rowsperstrip));
```
