# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3106_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3106_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 1106-1147 of the vulnerable file.

    *pixels;

  if (image->debug != MagickFalse)
    (void) LogMagickEvent(CoderEvent,GetMagickModule(),
       "      layer data is RLE compressed");

  row_size=GetPSDRowSize(image);
  pixels=(unsigned char *) AcquireQuantumMemory(row_size,sizeof(*pixels));
  if (pixels == (unsigned char *) NULL)
    ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
      image->filename);

  length=0;
  for (y=0; y < (ssize_t) image->rows; y++)
    if ((MagickOffsetType) length < sizes[y])
      length=(size_t) sizes[y];

  if (length > row_size + 256) // arbitrary number
    {
      pixels=(unsigned char *) RelinquishMagickMemory(pixels);
      ThrowBinaryException(ResourceLimitError,"InvalidLength",
        image->filename);
    }

  compact_pixels=(unsigned char *) AcquireQuantumMemory(length,sizeof(*pixels));
  if (compact_pixels == (unsigned char *) NULL)
    {
      pixels=(unsigned char *) RelinquishMagickMemory(pixels);
      ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
        image->filename);
    }

  (void) ResetMagickMemory(compact_pixels,0,length*sizeof(*compact_pixels));

  status=MagickTrue;
  for (y=0; y < (ssize_t) image->rows; y++)
  {
    status=MagickFalse;

    count=ReadBlob(image,(size_t) sizes[y],compact_pixels);
    if (count != (ssize_t) sizes[y])
      break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1123,8 +1123,7 @@
   if (length > row_size + 256) // arbitrary number
     {
       pixels=(unsigned char *) RelinquishMagickMemory(pixels);
-      ThrowBinaryException(ResourceLimitError,"InvalidLength",
-        image->filename);
+      ThrowBinaryException(ResourceLimitError,"InvalidLength",image->filename);
     }
 
   compact_pixels=(unsigned char *) AcquireQuantumMemory(length,sizeof(*pixels));
@@ -1665,8 +1664,8 @@
                 if (DiscardBlobBytes(image,(MagickSizeType) (length-18)) == MagickFalse)
                   {
                     layer_info=DestroyLayerInfo(layer_info,number_layers);
-                    ThrowBinaryException(CorruptImageError,"UnexpectedEndOfFile",
-                      image->filename);
+                    ThrowBinaryException(CorruptImageError,
+                      "UnexpectedEndOfFile",image->filename);
                   }
               }
             length=ReadBlobLong(image);
@@ -2610,8 +2609,7 @@
   if (compact_pixels == (unsigned char *) NULL)
     {
       (void) ThrowMagickException(exception,GetMagickModule(),
-        ResourceLimitError,"MemoryAllocationFailed","`%s'",
-        image->filename);
+        ResourceLimitError,"MemoryAllocationFailed","`%s'",image->filename);
     }
   return(compact_pixels);
 }
@@ -2642,7 +2640,7 @@
   compact_pixels=(unsigned char *) NULL;
   if (next_image->compression == RLECompression)
     {
-      compact_pixels=AcquireCompactPixels(image,exception);
+      compact_pixels=AcquireCompactPixels(next_image,exception);
       if (compact_pixels == (unsigned char *) NULL)
         return(0);
     }
```
