# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4774_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4774_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 308-348 of the vulnerable file.

      if (image->scene >= (image_info->scene+image_info->number_scenes-1))
        break;
    status=SetImageExtent(image,image->columns,image->rows);
    if (status == MagickFalse)
      {
        InheritException(exception,&image->exception);
        return(DestroyImageList(image));
      }
    /*
      Allocate RLE pixels.
    */
    if (image->matte != MagickFalse)
      number_planes++;
    number_pixels=(MagickSizeType) image->columns*image->rows;
    number_planes_filled=(number_planes % 2 == 0) ? number_planes :
      number_planes+1;
    if ((number_pixels*number_planes_filled) != (size_t) (number_pixels*
         number_planes_filled))
      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
    pixel_info=AcquireVirtualMemory(image->columns,image->rows*
      number_planes_filled*sizeof(*pixels));
    if (pixel_info == (MemoryInfo *) NULL)
      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
    pixel_info_length=image->columns*image->rows*number_planes_filled;
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
          if (image->matte == MagickFalse)
            for (j=0; j < (ssize_t) number_planes; j++)
              *p++=background_color[j];
          else
            {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -325,10 +325,11 @@
          number_planes_filled))
       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
     pixel_info=AcquireVirtualMemory(image->columns,image->rows*
-      number_planes_filled*sizeof(*pixels));
+      MagickMax(number_planes_filled,4)*sizeof(*pixels));
     if (pixel_info == (MemoryInfo *) NULL)
       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
-    pixel_info_length=image->columns*image->rows*number_planes_filled;
+    pixel_info_length=image->columns*image->rows*
+      MagickMax(number_planes_filled,4);
     pixels=(unsigned char *) GetVirtualMemoryBlob(pixel_info);
     if ((flags & 0x01) && !(flags & 0x02))
       {
```
