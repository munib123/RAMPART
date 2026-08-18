# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2830_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2830_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 197-237 of the vulnerable file.

          image->filename);
    }
  /*
    Allocate memory for a scanline.
  */
  if (interlace == NoInterlace)
    scanline=(unsigned char *) AcquireQuantumMemory((size_t) (2UL*
      image->columns+2UL),(size_t) quantum*sizeof(*scanline));
  else
    scanline=(unsigned char *) AcquireQuantumMemory(image->columns,
      (size_t) quantum*sizeof(*scanline));
  if (scanline == (unsigned char *) NULL)
    ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
  status=MagickTrue;
  do
  {
    chroma_image=CloneImage(image,(image->columns+horizontal_factor-1)/
      horizontal_factor,(image->rows+vertical_factor-1)/vertical_factor,
      MagickTrue,exception);
    if (chroma_image == (Image *) NULL)
      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
    /*
      Convert raster image to pixel packets.
    */
    if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
      if (image->scene >= (image_info->scene+image_info->number_scenes-1))
        break;
    status=SetImageExtent(image,image->columns,image->rows,exception);
    if (status == MagickFalse)
      break;
    if (interlace == PartitionInterlace)
      {
        AppendImageFormat("Y",image->filename);
        status=OpenBlob(image_info,image,ReadBinaryBlobMode,exception);
        if (status == MagickFalse)
          {
            image=DestroyImageList(image);
            return((Image *) NULL);
          }
      }
    for (y=0; y < (ssize_t) image->rows; y++)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -214,7 +214,10 @@
       horizontal_factor,(image->rows+vertical_factor-1)/vertical_factor,
       MagickTrue,exception);
     if (chroma_image == (Image *) NULL)
-      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+      {
+        scanline=(unsigned char *) RelinquishMagickMemory(scanline); 
+        ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+      }
     /*
       Convert raster image to pixel packets.
     */
@@ -230,6 +233,7 @@
         status=OpenBlob(image_info,image,ReadBinaryBlobMode,exception);
         if (status == MagickFalse)
           {
+            scanline=(unsigned char *) RelinquishMagickMemory(scanline); 
             image=DestroyImageList(image);
             return((Image *) NULL);
           }
@@ -356,6 +360,7 @@
         status=OpenBlob(image_info,image,ReadBinaryBlobMode,exception);
         if (status == MagickFalse)
           {
+            scanline=(unsigned char *) RelinquishMagickMemory(scanline); 
             image=DestroyImageList(image);
             return((Image *) NULL);
           }
@@ -402,6 +407,7 @@
           status=OpenBlob(image_info,image,ReadBinaryBlobMode,exception);
           if (status == MagickFalse)
             {
+              scanline=(unsigned char *) RelinquishMagickMemory(scanline); 
               image=DestroyImageList(image);
               return((Image *) NULL);
             }
@@ -445,7 +451,10 @@
       TriangleFilter,exception);
     chroma_image=DestroyImage(chroma_image);
     if (resize_image == (Image *) NULL)
-      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+      {
+        scanline=(unsigned char *) RelinquishMagickMemory(scanline);   
+        ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+      }
     for (y=0; y < (ssize_t) image->rows; y++)
     {
       q=GetAuthenticPixels(image,0,y,image->columns,1,exception);
@@ -494,6 +503,7 @@
         AcquireNextImage(image_info,image,exception);
         if (GetNextImageInList(image) == (Image *) NULL)
           {
+            scanline=(unsigned char *) RelinquishMagickMemory(scanline); 
             image=DestroyImageList(image);
             return((Image *) NULL);
           }
```
