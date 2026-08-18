# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1016_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1016_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 225-265 of the vulnerable file.

    }
  /*
     Read in header information.
  */
  count=ReadBlob(image,sz_XWDheader,(unsigned char *) &header);
  if (count != sz_XWDheader)
    ThrowReaderException(CorruptImageError,"UnableToReadImageHeader");
  /*
    Ensure the header byte-order is most-significant byte first.
  */
  lsb_first=1;
  if ((int) (*(char *) &lsb_first) != 0)
    MSBOrderLong((unsigned char *) &header,sz_XWDheader);
  /*
    Check to see if the dump file is in the proper format.
  */
  if (header.file_version != XWD_FILE_VERSION)
    ThrowReaderException(CorruptImageError,"FileFormatVersionMismatch");
  if (header.header_size < sz_XWDheader)
    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
  switch (header.visual_class)
  {
    case StaticGray:
    case GrayScale:
    {
      if (header.bits_per_pixel != 1)
        ThrowReaderException(CorruptImageError,"ImproperImageHeader");
      break;
    }
    case StaticColor:
    case PseudoColor:
    {
      if ((header.bits_per_pixel < 1) || (header.bits_per_pixel > 15) ||
          (header.ncolors == 0))
        ThrowReaderException(CorruptImageError,"ImproperImageHeader");
      break;
    }
    case TrueColor:
    case DirectColor:
    {
      if ((header.bits_per_pixel != 16) && (header.bits_per_pixel != 24) &&
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -242,6 +242,8 @@
     ThrowReaderException(CorruptImageError,"FileFormatVersionMismatch");
   if (header.header_size < sz_XWDheader)
     ThrowReaderException(CorruptImageError,"ImproperImageHeader");
+  if ((MagickSizeType) header.xoffset >= GetBlobSize(image))
+    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
   switch (header.visual_class)
   {
     case StaticGray:
@@ -255,7 +257,7 @@
     case PseudoColor:
     {
       if ((header.bits_per_pixel < 1) || (header.bits_per_pixel > 15) ||
-          (header.ncolors == 0))
+          (header.colormap_entries == 0))
         ThrowReaderException(CorruptImageError,"ImproperImageHeader");
       break;
     }
@@ -322,8 +324,6 @@
     default:
       ThrowReaderException(CorruptImageError,"ImproperImageHeader");
   }
-  if (header.ncolors > 65535)
-    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
   if (((header.bitmap_pad % 8) != 0) || (header.bitmap_pad > 32))
     ThrowReaderException(CorruptImageError,"ImproperImageHeader");
   length=(size_t) (header.header_size-sz_XWDheader);
@@ -391,8 +391,10 @@
       XWDColor
         color;
 
-      colors=(XColor *) AcquireQuantumMemory((size_t) header.ncolors,
-        sizeof(*colors));
+      length=(size_t) header.ncolors;
+      if (length > ((~0UL)/sizeof(*colors)))
+        ThrowReaderException(CorruptImageError,"ImproperImageHeader");
+      colors=(XColor *) AcquireQuantumMemory(length,sizeof(*colors));
       if (colors == (XColor *) NULL)
         {
           ximage=(XImage *) RelinquishMagickMemory(ximage);
@@ -694,6 +696,7 @@
   entry->encoder=(EncodeImageHandler *) WriteXWDImage;
 #endif
   entry->magick=(IsImageFormatHandler *) IsXWD;
+  entry->flags|=CoderDecoderSeekableStreamFlag;
   entry->flags^=CoderAdjoinFlag;
   (void) RegisterMagickInfo(entry);
   return(MagickImageCoderSignature);
```
