# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3105_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3105_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 2595-2635 of the vulnerable file.

    *mask;

  MagickOffsetType
    rows_offset;

  size_t
    channels,
    count,
    length,
    offset_length;

  unsigned char
    *compact_pixels;

  count=0;
  offset_length=0;
  rows_offset=0;
  compact_pixels=(unsigned char *) NULL;
  if (next_image->compression == RLECompression)
    {
      compact_pixels=AcquireCompactPixels(image);
      if (compact_pixels == (unsigned char *) NULL)
        return(0);
    }
  channels=1;
  if (separate == MagickFalse)
    {
      if (next_image->storage_class != PseudoClass)
        {
          if (IsGrayImage(next_image,&next_image->exception) == MagickFalse)
            channels=next_image->colorspace == CMYKColorspace ? 4 : 3;
          if (next_image->matte != MagickFalse)
            channels++;
        }
      rows_offset=TellBlob(image)+2;
      count+=WriteCompressionStart(psd_info,image,next_image,channels);
      offset_length=(next_image->rows*(psd_info->version == 1 ? 2 : 4));
    }
  size_offset+=2;
  if (next_image->storage_class == PseudoClass)
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2612,7 +2612,7 @@
   compact_pixels=(unsigned char *) NULL;
   if (next_image->compression == RLECompression)
     {
-      compact_pixels=AcquireCompactPixels(image);
+      compact_pixels=AcquireCompactPixels(next_image);
       if (compact_pixels == (unsigned char *) NULL)
         return(0);
     }
```
