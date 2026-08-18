# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2575_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2575_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1282-1322 of the vulnerable file.

  if (status == MagickFalse)
    {
      jpeg_destroy_decompress(&jpeg_info);
      InheritException(exception,&image->exception);
      return(DestroyImageList(image));
    }
  if ((jpeg_info.output_components != 1) &&
      (jpeg_info.output_components != 3) && (jpeg_info.output_components != 4))
    {
      jpeg_destroy_decompress(&jpeg_info);
      ThrowReaderException(CorruptImageError,"ImageTypeNotSupported");
    }
  memory_info=AcquireVirtualMemory((size_t) image->columns,
    jpeg_info.output_components*sizeof(*jpeg_pixels));
  if (memory_info == (MemoryInfo *) NULL)
    {
      jpeg_destroy_decompress(&jpeg_info);
      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
    }
  jpeg_pixels=(JSAMPLE *) GetVirtualMemoryBlob(memory_info);
  /*
    Convert JPEG pixels to pixel packets.
  */
  if (setjmp(error_manager.error_recovery) != 0)
    {
      if (memory_info != (MemoryInfo *) NULL)
        memory_info=RelinquishVirtualMemory(memory_info);
      jpeg_destroy_decompress(&jpeg_info);
      (void) CloseBlob(image);
      number_pixels=(MagickSizeType) image->columns*image->rows;
      if (number_pixels != 0)
        return(GetFirstImageInList(image));
      return(DestroyImage(image));
    }
  if (jpeg_info.quantize_colors != 0)
    {
      image->colors=(size_t) jpeg_info.actual_number_of_colors;
      if (jpeg_info.out_color_space == JCS_GRAYSCALE)
        for (i=0; i < (ssize_t) image->colors; i++)
        {
          image->colormap[i].red=ScaleCharToQuantum(jpeg_info.colormap[0][i]);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1299,6 +1299,8 @@
       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
     }
   jpeg_pixels=(JSAMPLE *) GetVirtualMemoryBlob(memory_info);
+  (void) ResetMagickMemory(jpeg_pixels,0,image->columns* 
+    jpeg_info.output_components*sizeof(*jpeg_pixels));
   /*
     Convert JPEG pixels to pixel packets.
   */
```
