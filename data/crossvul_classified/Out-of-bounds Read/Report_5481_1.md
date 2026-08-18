# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5481_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5481_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 802-842 of the vulnerable file.

  {
     TIFFError("readContigTilesIntoBuffer", "Tile size or tile rowsize is zero");
     exit(-1);
  }

  if (tilesize < (tsize_t)(tl * tile_rowsize))
    {
#ifdef DEBUG2
    TIFFError("readContigTilesIntoBuffer",
	      "Tilesize %lu is too small, using alternate calculation %u",
              tilesize, tl * tile_rowsize);
#endif
    tile_buffsize = tl * tile_rowsize;
    if (tl != (tile_buffsize / tile_rowsize))
    {
    	TIFFError("readContigTilesIntoBuffer", "Integer overflow when calculating buffer size.");
        exit(-1);
    }
    }

  tilebuf = _TIFFmalloc(tile_buffsize);
  if (tilebuf == 0)
    return 0;

  dst_rowsize = ((imagewidth * bps * spp) + 7) / 8;  
  for (row = 0; row < imagelength; row += tl)
    {
    nrow = (row + tl > imagelength) ? imagelength - row : tl;
    for (col = 0; col < imagewidth; col += tw)
      {
      tbytes = TIFFReadTile(in, tilebuf, col, row, 0, 0);
      if (tbytes < tilesize  && !ignore)
        {
	TIFFError(TIFFFileName(in),
		  "Error, can't read tile at row %lu col %lu, Read %lu bytes of %lu",
		  (unsigned long) col, (unsigned long) row, (unsigned long)tbytes,
                  (unsigned long)tilesize);
		  status = 0;
                  _TIFFfree(tilebuf);
		  return status;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -819,9 +819,18 @@
     }
     }
 
-  tilebuf = _TIFFmalloc(tile_buffsize);
+  /* Add 3 padding bytes for extractContigSamplesShifted32bits */
+  if( tile_buffsize > 0xFFFFFFFFU - 3 )
+  {
+      TIFFError("readContigTilesIntoBuffer", "Integer overflow when calculating buffer size.");
+      exit(-1);
+  }
+  tilebuf = _TIFFmalloc(tile_buffsize + 3);
   if (tilebuf == 0)
     return 0;
+  tilebuf[tile_buffsize] = 0;
+  tilebuf[tile_buffsize+1] = 0;
+  tilebuf[tile_buffsize+2] = 0;
 
   dst_rowsize = ((imagewidth * bps * spp) + 7) / 8;  
   for (row = 0; row < imagelength; row += tl)
```
