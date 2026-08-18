# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 3361_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3361_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 314-354 of the vulnerable file.

    if (status == MagickFalse)
      return(DestroyImageList(image));
    /*
      Allocate RLE pixels.
    */
    if (image->alpha_trait != UndefinedPixelTrait)
      number_planes++;
    number_pixels=(MagickSizeType) image->columns*image->rows;
    number_planes_filled=(number_planes % 2 == 0) ? number_planes :
      number_planes+1;
    if ((number_pixels*number_planes_filled) != (size_t) (number_pixels*
         number_planes_filled))
      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
    pixel_info=AcquireVirtualMemory(image->columns,image->rows*
      MagickMax(number_planes_filled,4)*sizeof(*pixels));
    if (pixel_info == (MemoryInfo *) NULL)
      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
    pixel_info_length=image->columns*image->rows*
      MagickMax(number_planes_filled,4);
    pixels=(unsigned char *) GetVirtualMemoryBlob(pixel_info);
    if ((flags & 0x01) && !(flags & 0x02))
      {
        ssize_t
          j;

        /*
          Set background color.
        */
        p=pixels;
        for (i=0; i < (ssize_t) number_pixels; i++)
        {
          if (image->alpha_trait == UndefinedPixelTrait)
            for (j=0; j < (ssize_t) number_planes; j++)
              *p++=background_color[j];
          else
            {
              for (j=0; j < (ssize_t) (number_planes-1); j++)
                *p++=background_color[j];
              *p++=0;  /* initialize matte channel */
            }
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -331,6 +331,7 @@
     pixel_info_length=image->columns*image->rows*
       MagickMax(number_planes_filled,4);
     pixels=(unsigned char *) GetVirtualMemoryBlob(pixel_info);
+    (void) ResetMagickMemory(pixels,0,pixel_info_length);
     if ((flags & 0x01) && !(flags & 0x02))
       {
         ssize_t
```
