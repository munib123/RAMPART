# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5480_2
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5480_2`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 3611-3651 of the vulnerable file.

      case 3:
      case 4: 
      case 5: if (extractContigSamples32bits (src, dst, cols, sample,
                                              spp, bps,  count, 0, cols))
	         return (1);
	      break;
      default: TIFFError ("extractContigSamplesToTileBuffer", "Unsupported bit depth: %d", bps);
	       return (1);
      }
    if ((dump->outfile != NULL) && (dump->level == 4))
      dump_buffer(dump->outfile, dump->format, 1, dst_rowsize, row, dst);
    }

  return (0);
  } /* end extractContigSamplesToTileBuffer */

static int readContigStripsIntoBuffer (TIFF* in, uint8* buf)
{
        uint8* bufp = buf;
        int32  bytes_read = 0;
        uint16 strip, nstrips   = TIFFNumberOfStrips(in);
        uint32 stripsize = TIFFStripSize(in);
        uint32 rows = 0;
        uint32 rps = TIFFGetFieldDefaulted(in, TIFFTAG_ROWSPERSTRIP, &rps);
        tsize_t scanline_size = TIFFScanlineSize(in);

        if (scanline_size == 0) {
                TIFFError("", "TIFF scanline size is zero!");    
                return 0;
        }

        for (strip = 0; strip < nstrips; strip++) {
                bytes_read = TIFFReadEncodedStrip (in, strip, bufp, -1);
                rows = bytes_read / scanline_size;
                if ((strip < (nstrips - 1)) && (bytes_read != (int32)stripsize))
                        TIFFError("", "Strip %d: read %lu bytes, strip size %lu",
                                  (int)strip + 1, (unsigned long) bytes_read,
                                  (unsigned long)stripsize);

                if (bytes_read < 0 && !ignore) {
                        TIFFError("", "Error reading strip %lu after %lu rows",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3628,7 +3628,7 @@
 {
         uint8* bufp = buf;
         int32  bytes_read = 0;
-        uint16 strip, nstrips   = TIFFNumberOfStrips(in);
+        uint32 strip, nstrips   = TIFFNumberOfStrips(in);
         uint32 stripsize = TIFFStripSize(in);
         uint32 rows = 0;
         uint32 rps = TIFFGetFieldDefaulted(in, TIFFTAG_ROWSPERSTRIP, &rps);
@@ -4711,9 +4711,12 @@
                                          uint32 width, uint16 spp,
                                          struct dump_opts *dump)
   {
-  int i, j, bytes_per_sample, bytes_per_pixel, shift_width, result = 1;
+  int i, bytes_per_sample, bytes_per_pixel, shift_width, result = 1;
+  uint32 j;
   int32  bytes_read = 0;
-  uint16 bps, nstrips, planar, strips_per_sample;
+  uint16 bps, planar;
+  uint32 nstrips;
+  uint32 strips_per_sample;
   uint32 src_rowsize, dst_rowsize, rows_processed, rps;
   uint32 rows_this_strip = 0;
   tsample_t s;
```
