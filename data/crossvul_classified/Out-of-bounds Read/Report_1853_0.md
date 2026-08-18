# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1853_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1853_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 243-284 of the vulnerable file.


  MagickBooleanType
    status;

  MagickSizeType
    number_pixels;

  register Quantum
    *q;

  register ssize_t
    i,
    x;

  register unsigned char
    *p;

  size_t
    bytes_per_line,
    extent,
    height,
    length;

  ssize_t
    count,
    y;

  SUNInfo
    sun_info;

  unsigned char
    *sun_data,
    *sun_pixels;

  /*
    Open image file.
  */
  assert(image_info != (const ImageInfo *) NULL);
  assert(image_info->signature == MagickSignature);
  if (image_info->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",
      image_info->filename);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -260,8 +260,7 @@
   size_t
     bytes_per_line,
     extent,
-    height,
-    length;
+    height;
 
   ssize_t
     count,
@@ -494,13 +493,6 @@
     else
       if (image->storage_class == PseudoClass)
         {
-          if (bytes_per_line == 0)
-            bytes_per_line=image->columns;
-          length=image->rows*(image->columns+image->columns % 2);
-          if (((sun_info.type == RT_ENCODED) &&
-               (length > (bytes_per_line*image->rows))) ||
-              ((sun_info.type != RT_ENCODED) && (length > sun_info.length)))
-            ThrowReaderException(CorruptImageError,"UnableToReadImageData");
           for (y=0; y < (ssize_t) image->rows; y++)
           {
             q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
@@ -534,11 +526,6 @@
             bytes_per_pixel++;
           if (bytes_per_line == 0)
             bytes_per_line=bytes_per_pixel*image->columns;
-          length=image->rows*(bytes_per_line+bytes_per_line % 2);
-          if (((sun_info.type == RT_ENCODED) &&
-               (length > (bytes_per_line*image->rows))) ||
-              ((sun_info.type != RT_ENCODED) && (length > sun_info.length)))
-            ThrowReaderException(CorruptImageError,"UnableToReadImageData");
           for (y=0; y < (ssize_t) image->rows; y++)
           {
             q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
```
