# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3104_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3104_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1595-1636 of the vulnerable file.

        (photometric != PHOTOMETRIC_CIELAB) &&
        (photometric != PHOTOMETRIC_SEPARATED))
      method=ReadGenericMethod;
    if (image->storage_class == PseudoClass)
      method=ReadSingleSampleMethod;
    if ((photometric == PHOTOMETRIC_MINISBLACK) ||
        (photometric == PHOTOMETRIC_MINISWHITE))
      method=ReadSingleSampleMethod;
    if ((photometric != PHOTOMETRIC_SEPARATED) &&
        (interlace == PLANARCONFIG_SEPARATE) && (bits_per_sample < 64))
      method=ReadGenericMethod;
    if (image->compression == JPEGCompression)
      method=GetJPEGMethod(image,tiff,photometric,bits_per_sample,
        samples_per_pixel);
    if (compress_tag == COMPRESSION_JBIG)
      method=ReadStripMethod;
    if (TIFFIsTiled(tiff) != MagickFalse)
      method=ReadTileMethod;
    quantum_info->endian=LSBEndian;
    quantum_type=RGBQuantum;
    tiff_pixels=(unsigned char *) AcquireMagickMemory(TIFFScanlineSize(tiff)+
      sizeof(uint32));
    if (tiff_pixels == (unsigned char *) NULL)
      {
        TIFFClose(tiff);
        ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
      }
    switch (method)
    {
      case ReadSingleSampleMethod:
      {
        /*
          Convert TIFF image to PseudoClass MIFF image.
        */
        quantum_type=IndexQuantum;
        pad=(size_t) MagickMax((size_t) samples_per_pixel-1,0);
        if (image->matte != MagickFalse)
          {
            if (image->storage_class != PseudoClass)
              {
                quantum_type=samples_per_pixel == 1 ? AlphaQuantum :
                  GrayAlphaQuantum;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1612,8 +1612,9 @@
       method=ReadTileMethod;
     quantum_info->endian=LSBEndian;
     quantum_type=RGBQuantum;
-    tiff_pixels=(unsigned char *) AcquireMagickMemory(TIFFScanlineSize(tiff)+
-      sizeof(uint32));
+    tiff_pixels=(unsigned char *) AcquireMagickMemory(MagickMax(
+      TIFFScanlineSize(tiff),(size_t) (image->columns*samples_per_pixel*
+      pow(2.0,ceil(log(bits_per_sample)/log(2.0))))));
     if (tiff_pixels == (unsigned char *) NULL)
       {
         TIFFClose(tiff);
```
