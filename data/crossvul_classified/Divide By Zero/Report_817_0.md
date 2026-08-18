# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 817_0
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `817_0`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 229-269 of the vulnerable file.

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
  if ((header.bits_per_pixel == 0) || (header.bits_per_pixel > 32))
    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
  if (((header.bitmap_pad % 8) != 0) || (header.bitmap_pad > 32))
    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
  if (header.bitmap_unit > 32)
    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
  if (header.ncolors > 256)
    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
  switch (header.visual_class)
  {
    case StaticGray:
    case GrayScale:
    case StaticColor:
    case PseudoColor:
    case TrueColor:
    case DirectColor:
      break;
    default:
      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
  }
  switch (header.pixmap_format)
  {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -246,6 +246,9 @@
   if (header.header_size < sz_XWDheader)
     ThrowReaderException(CorruptImageError,"ImproperImageHeader");
   if ((header.bits_per_pixel == 0) || (header.bits_per_pixel > 32))
+    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
+  if ((header.bitmap_bit_order != MSBFirst) &&
+      (header.bitmap_bit_order != LSBFirst))
     ThrowReaderException(CorruptImageError,"ImproperImageHeader");
   if (((header.bitmap_pad % 8) != 0) || (header.bitmap_pad > 32))
     ThrowReaderException(CorruptImageError,"ImproperImageHeader");
```
