# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2622_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2622_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 1004-1044 of the vulnerable file.

      ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
    (void) memset(pcx_colormap,0,3*256*sizeof(*pcx_colormap));
    q=pcx_colormap;
    if ((image->storage_class == PseudoClass) && (image->colors <= 256))
      for (i=0; i < (ssize_t) image->colors; i++)
      {
        *q++=ScaleQuantumToChar(image->colormap[i].red);
        *q++=ScaleQuantumToChar(image->colormap[i].green);
        *q++=ScaleQuantumToChar(image->colormap[i].blue);
      }
    (void) WriteBlob(image,3*16,(const unsigned char *) pcx_colormap);
    (void) WriteBlobByte(image,pcx_info.reserved);
    (void) WriteBlobByte(image,pcx_info.planes);
    (void) WriteBlobLSBShort(image,pcx_info.bytes_per_line);
    (void) WriteBlobLSBShort(image,pcx_info.palette_info);
    for (i=0; i < 58; i++)
      (void) WriteBlobByte(image,'\0');
    length=(size_t) pcx_info.bytes_per_line;
    pixel_info=AcquireVirtualMemory(length,pcx_info.planes*sizeof(*pixels));
    if (pixel_info == (MemoryInfo *) NULL)
      ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
    pixels=(unsigned char *) GetVirtualMemoryBlob(pixel_info);
    q=pixels;
    if ((image->storage_class == DirectClass) || (image->colors > 256))
      {
        /*
          Convert DirectClass image to PCX raster pixels.
        */
        for (y=0; y < (ssize_t) image->rows; y++)
        {
          q=pixels;
          for (i=0; i < pcx_info.planes; i++)
          {
            p=GetVirtualPixels(image,0,y,image->columns,1,&image->exception);
            if (p == (const PixelPacket *) NULL)
              break;
            switch ((int) i)
            {
              case 0:
              {
                for (x=0; x < (ssize_t) pcx_info.bytes_per_line; x++)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1021,7 +1021,10 @@
     length=(size_t) pcx_info.bytes_per_line;
     pixel_info=AcquireVirtualMemory(length,pcx_info.planes*sizeof(*pixels));
     if (pixel_info == (MemoryInfo *) NULL)
-      ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
+      {
+        pcx_colormap=(unsigned char *) RelinquishMagickMemory(pcx_colormap);
+        ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
+      }
     pixels=(unsigned char *) GetVirtualMemoryBlob(pixel_info);
     q=pixels;
     if ((image->storage_class == DirectClass) || (image->colors > 256))
```
