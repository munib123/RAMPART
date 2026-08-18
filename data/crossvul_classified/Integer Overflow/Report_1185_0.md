# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 1185_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1185_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 932-972 of the vulnerable file.

		return (0);
	}
	
	maxstripsize = TIFFStripSize(tif);

	flip = setorientation(img);
	if (flip & FLIP_VERTICALLY) {
		y = h - 1;
		toskew = -(int32)(w + w);
	} else {
		y = 0;
		toskew = -(int32)(w - w);
	}

	TIFFGetFieldDefaulted(tif, TIFFTAG_ROWSPERSTRIP, &rowsperstrip);

	scanline = TIFFScanlineSize(tif);
	fromskew = (w < imagewidth ? imagewidth - w : 0);
	for (row = 0; row < h; row += nrow)
	{
		rowstoread = rowsperstrip - (row + img->row_offset) % rowsperstrip;
		nrow = (row + rowstoread > h ? h - row : rowstoread);
		nrowsub = nrow;
		if ((nrowsub%subsamplingver)!=0)
			nrowsub+=subsamplingver-nrowsub%subsamplingver;
		if (_TIFFReadEncodedStripAndAllocBuffer(tif,
		    TIFFComputeStrip(tif,row+img->row_offset, 0),
		    (void**)(&buf),
                    maxstripsize,
		    ((row + img->row_offset)%rowsperstrip + nrowsub) * scanline)==(tmsize_t)(-1)
		    && (buf == NULL || img->stoponerr))
		{
			ret = 0;
			break;
		}

		pos = ((row + img->row_offset) % rowsperstrip) * scanline + \
			((tmsize_t) img->col_offset * img->samplesperpixel);
		(*put)(img, raster+y*w, 0, y, w, nrow, fromskew, toskew, buf + pos);
		y += ((flip & FLIP_VERTICALLY) ? -(int32) nrow : (int32) nrow);
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -949,16 +949,23 @@
 	fromskew = (w < imagewidth ? imagewidth - w : 0);
 	for (row = 0; row < h; row += nrow)
 	{
+		uint32 temp;
 		rowstoread = rowsperstrip - (row + img->row_offset) % rowsperstrip;
 		nrow = (row + rowstoread > h ? h - row : rowstoread);
 		nrowsub = nrow;
 		if ((nrowsub%subsamplingver)!=0)
 			nrowsub+=subsamplingver-nrowsub%subsamplingver;
+		temp = (row + img->row_offset)%rowsperstrip + nrowsub;
+		if( scanline > 0 && temp > (size_t)(TIFF_TMSIZE_T_MAX / scanline) )
+		{
+			TIFFErrorExt(tif->tif_clientdata, TIFFFileName(tif), "Integer overflow in gtStripContig");
+			return 0;
+		}
 		if (_TIFFReadEncodedStripAndAllocBuffer(tif,
 		    TIFFComputeStrip(tif,row+img->row_offset, 0),
 		    (void**)(&buf),
                     maxstripsize,
-		    ((row + img->row_offset)%rowsperstrip + nrowsub) * scanline)==(tmsize_t)(-1)
+		    temp * scanline)==(tmsize_t)(-1)
 		    && (buf == NULL || img->stoponerr))
 		{
 			ret = 0;
@@ -1051,15 +1058,22 @@
 	fromskew = (w < imagewidth ? imagewidth - w : 0);
 	for (row = 0; row < h; row += nrow)
 	{
+                uint32 temp;
 		rowstoread = rowsperstrip - (row + img->row_offset) % rowsperstrip;
 		nrow = (row + rowstoread > h ? h - row : rowstoread);
 		offset_row = row + img->row_offset;
+                temp = (row + img->row_offset)%rowsperstrip + nrow;
+                if( scanline > 0 && temp > (size_t)(TIFF_TMSIZE_T_MAX / scanline) )
+                {
+                        TIFFErrorExt(tif->tif_clientdata, TIFFFileName(tif), "Integer overflow in gtStripSeparate");
+                        return 0;
+                }
                 if( buf == NULL )
                 {
                     if (_TIFFReadEncodedStripAndAllocBuffer(
                             tif, TIFFComputeStrip(tif, offset_row, 0),
                             (void**) &buf, bufsize,
-                            ((row + img->row_offset)%rowsperstrip + nrow) * scanline)==(tmsize_t)(-1)
+                            temp * scanline)==(tmsize_t)(-1)
                         && (buf == NULL || img->stoponerr))
                     {
                             ret = 0;
@@ -1079,7 +1093,7 @@
                     }
                 }
 		else if (TIFFReadEncodedStrip(tif, TIFFComputeStrip(tif, offset_row, 0),
-		    p0, ((row + img->row_offset)%rowsperstrip + nrow) * scanline)==(tmsize_t)(-1)
+		    p0, temp * scanline)==(tmsize_t)(-1)
 		    && img->stoponerr)
 		{
 			ret = 0;
@@ -1087,7 +1101,7 @@
 		}
 		if (colorchannels > 1 
                     && TIFFReadEncodedStrip(tif, TIFFComputeStrip(tif, offset_row, 1),
-                                            p1, ((row + img->row_offset)%rowsperstrip + nrow) * scanline) == (tmsize_t)(-1)
+                                            p1, temp * scanline) == (tmsize_t)(-1)
 		    && img->stoponerr)
 		{
 			ret = 0;
@@ -1095,7 +1109,7 @@
 		}
 		if (colorchannels > 1 
                     && TIFFReadEncodedStrip(tif, TIFFComputeStrip(tif, offset_row, 2),
-                                            p2, ((row + img->row_offset)%rowsperstrip + nrow) * scanline) == (tmsize_t)(-1)
+                                            p2, temp * scanline) == (tmsize_t)(-1)
 		    && img->stoponerr)
 		{
 			ret = 0;
@@ -1104,7 +1118,7 @@
 		if (alpha)
 		{
 			if (TIFFReadEncodedStrip(tif, TIFFComputeStrip(tif, offset_row, colorchannels),
-			    pa, ((row + img->row_offset)%rowsperstrip + nrow) * scanline)==(tmsize_t)(-1)
+			    pa, temp * scanline)==(tmsize_t)(-1)
 			    && img->stoponerr)
 			{
 				ret = 0;
```
