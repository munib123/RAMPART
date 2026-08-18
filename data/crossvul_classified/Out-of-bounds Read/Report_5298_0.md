# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5298_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5298_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 713-753 of the vulnerable file.

  */
  (void) ResetMagickMemory(header,' ',MagickPathExtent);
  length=CopyMagickString(header,"#?RGBE\n",MagickPathExtent);
  (void) WriteBlob(image,length,(unsigned char *) header);
  property=GetImageProperty(image,"comment",exception);
  if ((property != (const char *) NULL) &&
      (strchr(property,'\n') == (char *) NULL))
    {
      count=FormatLocaleString(header,MagickPathExtent,"#%s\n",property);
      (void) WriteBlob(image,(size_t) count,(unsigned char *) header);
    }
  property=GetImageProperty(image,"hdr:exposure",exception);
  if (property != (const char *) NULL)
    {
      count=FormatLocaleString(header,MagickPathExtent,"EXPOSURE=%g\n",
        strtod(property,(char **) NULL));
      (void) WriteBlob(image,(size_t) count,(unsigned char *) header);
    }
  if (image->gamma != 0.0)
    {
      count=FormatLocaleString(header,MagickPathExtent,"GAMMA=%g\n",image->gamma);
      (void) WriteBlob(image,(size_t) count,(unsigned char *) header);
    }
  count=FormatLocaleString(header,MagickPathExtent,
    "PRIMARIES=%g %g %g %g %g %g %g %g\n",
    image->chromaticity.red_primary.x,image->chromaticity.red_primary.y,
    image->chromaticity.green_primary.x,image->chromaticity.green_primary.y,
    image->chromaticity.blue_primary.x,image->chromaticity.blue_primary.y,
    image->chromaticity.white_point.x,image->chromaticity.white_point.y);
  (void) WriteBlob(image,(size_t) count,(unsigned char *) header);
  length=CopyMagickString(header,"FORMAT=32-bit_rle_rgbe\n\n",MagickPathExtent);
  (void) WriteBlob(image,length,(unsigned char *) header);
  count=FormatLocaleString(header,MagickPathExtent,"-Y %.20g +X %.20g\n",
    (double) image->rows,(double) image->columns);
  (void) WriteBlob(image,(size_t) count,(unsigned char *) header);
  /*
    Write HDR pixels.
  */
  pixels=(unsigned char *) AcquireQuantumMemory(image->columns,4*
    sizeof(*pixels));
  if (pixels == (unsigned char *) NULL)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -730,7 +730,8 @@
     }
   if (image->gamma != 0.0)
     {
-      count=FormatLocaleString(header,MagickPathExtent,"GAMMA=%g\n",image->gamma);
+      count=FormatLocaleString(header,MagickPathExtent,"GAMMA=%g\n",
+        image->gamma);
       (void) WriteBlob(image,(size_t) count,(unsigned char *) header);
     }
   count=FormatLocaleString(header,MagickPathExtent,
@@ -748,10 +749,11 @@
   /*
     Write HDR pixels.
   */
-  pixels=(unsigned char *) AcquireQuantumMemory(image->columns,4*
+  pixels=(unsigned char *) AcquireQuantumMemory(image->columns+128,4*
     sizeof(*pixels));
   if (pixels == (unsigned char *) NULL)
     ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
+  (void) ResetMagickMemory(pixels,0,4*(image->columns+128)*sizeof(*pixels));
   for (y=0; y < (ssize_t) image->rows; y++)
   {
     p=GetVirtualPixels(image,0,y,image->columns,1,exception);
```
