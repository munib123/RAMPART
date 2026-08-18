# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 5474_4
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5474_4`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 5741-5781 of the vulnerable file.

      x2 = (uint32)(owidth * (j + 1) - 1);
      if (x2 >= iwidth)
        x2 = iwidth - 1;
      sections[k].x1 = x1;
      sections[k].x2 = x2;
      sections[k].y1 = y1;
      sections[k].y2 = y2;
      sections[k].buffsize = line_bytes * olength;
      sections[k].position = k + 1;
      sections[k].total = orows * ocols;
      } 
    } 
  return (0);
  } /* end computeOutputPixelOffsets */

static int
loadImage(TIFF* in, struct image_data *image, struct dump_opts *dump, unsigned char **read_ptr)
  {
  uint32   i;
  float    xres = 0.0, yres = 0.0;
  uint16   nstrips = 0, ntiles = 0, planar = 0;
  uint16   bps = 0, spp = 0, res_unit = 0;
  uint16   orientation = 0;
  uint16   input_compression = 0, input_photometric = 0;
  uint16   subsampling_horiz, subsampling_vert;
  uint32   width = 0, length = 0;
  uint32   stsize = 0, tlsize = 0, buffsize = 0, scanlinesize = 0;
  uint32   tw = 0, tl = 0;       /* Tile width and length */
  uint32   tile_rowsize = 0;
  unsigned char *read_buff = NULL;
  unsigned char *new_buff  = NULL;
  int      readunit = 0;
  static   uint32  prev_readsize = 0;

  TIFFGetFieldDefaulted(in, TIFFTAG_BITSPERSAMPLE, &bps);
  TIFFGetFieldDefaulted(in, TIFFTAG_SAMPLESPERPIXEL, &spp);
  TIFFGetFieldDefaulted(in, TIFFTAG_PLANARCONFIG, &planar);
  TIFFGetFieldDefaulted(in, TIFFTAG_ORIENTATION, &orientation);
  if (! TIFFGetFieldDefaulted(in, TIFFTAG_PHOTOMETRIC, &input_photometric))
    TIFFError("loadImage","Image lacks Photometric interpreation tag");
  if (! TIFFGetField(in, TIFFTAG_IMAGEWIDTH,  &width))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5758,7 +5758,8 @@
   {
   uint32   i;
   float    xres = 0.0, yres = 0.0;
-  uint16   nstrips = 0, ntiles = 0, planar = 0;
+  uint32   nstrips = 0, ntiles = 0;
+  uint16   planar = 0;
   uint16   bps = 0, spp = 0, res_unit = 0;
   uint16   orientation = 0;
   uint16   input_compression = 0, input_photometric = 0;
@@ -6066,11 +6067,23 @@
   /* +3 : add a few guard bytes since reverseSamples16bits() can read a bit */
   /* outside buffer */
   if (!read_buff)
+  {
+    if( buffsize > 0xFFFFFFFFU - 3 )
+    {
+        TIFFError("loadImage", "Unable to allocate/reallocate read buffer");
+        return (-1);
+    }
     read_buff = (unsigned char *)_TIFFmalloc(buffsize+3);
+  }
   else
     {
     if (prev_readsize < buffsize)
-      {
+    {
+      if( buffsize > 0xFFFFFFFFU - 3 )
+      {
+          TIFFError("loadImage", "Unable to allocate/reallocate read buffer");
+          return (-1);
+      }
       new_buff = _TIFFrealloc(read_buff, buffsize+3);
       if (!new_buff)
         {
@@ -8912,6 +8925,11 @@
     }
 
   bytes_per_pixel  = ((bps * spp) + 7) / 8;
+  if( bytes_per_pixel > sizeof(swapbuff) )
+  {
+    TIFFError("reverseSamplesBytes","bytes_per_pixel too large");
+    return (1);
+  }
   switch (bps / 8)
      {
      case 8:  /* Use memcpy for multiple bytes per sample data */
```
