# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2583_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2583_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 8263-8303 of the vulnerable file.

    quality,
    rowbytes,
    save_image_depth;

  int
    j,
    number_colors,
    number_opaque,
    number_semitransparent,
    number_transparent,
    ping_pHYs_unit_type;

  png_uint_32
    ping_pHYs_x_resolution,
    ping_pHYs_y_resolution;

  logging=LogMagickEvent(CoderEvent,GetMagickModule(),
    "  Enter WriteOnePNGImage()");

  image = CloneImage(IMimage,0,0,MagickFalse,exception);
  image_info=(ImageInfo *) CloneImageInfo(IMimage_info);
  if (image_info == (ImageInfo *) NULL)
     ThrowWriterException(ResourceLimitError, "MemoryAllocationFailed");

  /* Define these outside of the following "if logging()" block so they will
   * show in debuggers.
   */
  *im_vers='\0';
  (void) ConcatenateMagickString(im_vers,
         MagickLibVersionText,MagickPathExtent);
  (void) ConcatenateMagickString(im_vers,
         MagickLibAddendum,MagickPathExtent);

  *libpng_vers='\0';
  (void) ConcatenateMagickString(libpng_vers,
         PNG_LIBPNG_VER_STRING,32);
  *libpng_runv='\0';
  (void) ConcatenateMagickString(libpng_runv,
         png_get_libpng_ver(NULL),32);

  *zlib_vers='\0';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8280,9 +8280,11 @@
     "  Enter WriteOnePNGImage()");
 
   image = CloneImage(IMimage,0,0,MagickFalse,exception);
+  if (image == (Image *) NULL)
+    return(MagickFalse);
   image_info=(ImageInfo *) CloneImageInfo(IMimage_info);
   if (image_info == (ImageInfo *) NULL)
-     ThrowWriterException(ResourceLimitError, "MemoryAllocationFailed");
+    ThrowWriterException(ResourceLimitError, "MemoryAllocationFailed");
 
   /* Define these outside of the following "if logging()" block so they will
    * show in debuggers.
```
