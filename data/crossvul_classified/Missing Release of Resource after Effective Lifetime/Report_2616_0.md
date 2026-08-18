# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2616_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2616_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 1996-2036 of the vulnerable file.

          {
            status=InjectImageBlob(image_info,image,image,"jp2",
              &image->exception);
            if (status == MagickFalse)
              ThrowWriterException(CoderError,image->exception.reason);
            break;
          }
          case RLECompression:
          default:
          {
            MemoryInfo
              *pixel_info;

            /*
              Allocate pixel array.
            */
            length=(size_t) number_pixels;
            length*=image->colorspace == CMYKColorspace ? 4UL : 3UL;
            pixel_info=AcquireVirtualMemory(length,sizeof(*pixels));
            if (pixel_info == (MemoryInfo *) NULL)
              ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
            pixels=(unsigned char *) GetVirtualMemoryBlob(pixel_info);
            /*
              Dump runlength encoded pixels.
            */
            q=pixels;
            for (y=0; y < (ssize_t) image->rows; y++)
            {
              p=GetVirtualPixels(image,0,y,image->columns,1,&image->exception);
              if (p == (const PixelPacket *) NULL)
                break;
              indexes=GetVirtualIndexQueue(image);
              for (x=0; x < (ssize_t) image->columns; x++)
              {
                *q++=ScaleQuantumToChar(GetPixelRed(p));
                *q++=ScaleQuantumToChar(GetPixelGreen(p));
                *q++=ScaleQuantumToChar(GetPixelBlue(p));
                if (image->colorspace == CMYKColorspace)
                  *q++=ScaleQuantumToChar(GetPixelIndex(indexes+x));
                p++;
              }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2013,7 +2013,11 @@
             length*=image->colorspace == CMYKColorspace ? 4UL : 3UL;
             pixel_info=AcquireVirtualMemory(length,sizeof(*pixels));
             if (pixel_info == (MemoryInfo *) NULL)
-              ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
+              {
+                xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
+                ThrowWriterException(ResourceLimitError,
+                  "MemoryAllocationFailed");
+              }
             pixels=(unsigned char *) GetVirtualMemoryBlob(pixel_info);
             /*
               Dump runlength encoded pixels.
@@ -2115,8 +2119,11 @@
               length=(size_t) number_pixels;
               pixel_info=AcquireVirtualMemory(length,sizeof(*pixels));
               if (pixel_info == (MemoryInfo *) NULL)
-                ThrowWriterException(ResourceLimitError,
-                  "MemoryAllocationFailed");
+                {
+                  xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
+                  ThrowWriterException(ResourceLimitError,
+                    "MemoryAllocationFailed");
+                }
               pixels=(unsigned char *) GetVirtualMemoryBlob(pixel_info);
               /*
                 Dump runlength encoded pixels.
```
