# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 4778_1
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4778_1`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 3463-3503 of the vulnerable file.

      }
      case SignedQuantumFormat:
      {
        (void) TIFFSetField(tiff,TIFFTAG_SAMPLEFORMAT,SAMPLEFORMAT_INT);
        break;
      }
      case UnsignedQuantumFormat:
      {
        (void) TIFFSetField(tiff,TIFFTAG_SAMPLEFORMAT,SAMPLEFORMAT_UINT);
        break;
      }
      default:
        break;
    }
    (void) TIFFSetField(tiff,TIFFTAG_ORIENTATION,ORIENTATION_TOPLEFT);
    (void) TIFFSetField(tiff,TIFFTAG_PLANARCONFIG,PLANARCONFIG_CONTIG);
    if (photometric == PHOTOMETRIC_RGB)
      if ((image_info->interlace == PlaneInterlace) ||
          (image_info->interlace == PartitionInterlace))
        (void) TIFFSetField(tiff,TIFFTAG_PLANARCONFIG,PLANARCONFIG_SEPARATE);
    rows_per_strip=TIFFDefaultStripSize(tiff,0);
    option=GetImageOption(image_info,"tiff:rows-per-strip");
    if (option != (const char *) NULL)
      rows_per_strip=(size_t) strtol(option,(char **) NULL,10);
    switch (compress_tag)
    {
      case COMPRESSION_JPEG:
      {
#if defined(JPEG_SUPPORT)
        const char
          *sampling_factor;

        GeometryInfo
          geometry_info;

        MagickStatusType
          flags;

        rows_per_strip+=(16-(rows_per_strip % 16));
        if (image_info->quality != UndefinedCompressionQuality)
          (void) TIFFSetField(tiff,TIFFTAG_JPEGQUALITY,image_info->quality);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3480,7 +3480,9 @@
       if ((image_info->interlace == PlaneInterlace) ||
           (image_info->interlace == PartitionInterlace))
         (void) TIFFSetField(tiff,TIFFTAG_PLANARCONFIG,PLANARCONFIG_SEPARATE);
-    rows_per_strip=TIFFDefaultStripSize(tiff,0);
+    rows_per_strip=1;
+    if (TIFFScanlineSize(tiff) != 0)
+      rows_per_strip=TIFFDefaultStripSize(tiff,0);
     option=GetImageOption(image_info,"tiff:rows-per-strip");
     if (option != (const char *) NULL)
       rows_per_strip=(size_t) strtol(option,(char **) NULL,10);
```
