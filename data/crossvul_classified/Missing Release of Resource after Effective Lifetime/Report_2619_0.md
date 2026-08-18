# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2619_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2619_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 1750-1790 of the vulnerable file.

      pixmap.component_count=image->matte != MagickFalse ? 4 : 3;
      pixmap.pixel_type=16;
      pixmap.bits_per_pixel=32;
      pixmap.pack_type=0x04;
      transfer_mode=0x40;
      row_bytes=4*image->columns;
    }
  /*
    Allocate memory.
  */
  bytes_per_line=image->columns;
  if (storage_class == DirectClass)
    bytes_per_line*=image->matte != MagickFalse ? 4 : 3;
  buffer=(unsigned char *) AcquireQuantumMemory(PictInfoSize,sizeof(*buffer));
  packed_scanline=(unsigned char *) AcquireQuantumMemory((size_t)
   (row_bytes+MaxCount),sizeof(*packed_scanline));
  scanline=(unsigned char *) AcquireQuantumMemory(row_bytes,sizeof(*scanline));
  if ((buffer == (unsigned char *) NULL) ||
      (packed_scanline == (unsigned char *) NULL) ||
      (scanline == (unsigned char *) NULL))
    ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
  (void) ResetMagickMemory(scanline,0,row_bytes);
  (void) ResetMagickMemory(packed_scanline,0,(size_t) (row_bytes+MaxCount));
  /*
    Write header, header size, size bounding box, version, and reserved.
  */
  (void) ResetMagickMemory(buffer,0,PictInfoSize);
  (void) WriteBlob(image,PictInfoSize,buffer);
  (void) WriteBlobMSBShort(image,0);
  (void) WriteBlobMSBShort(image,(unsigned short) size_rectangle.top);
  (void) WriteBlobMSBShort(image,(unsigned short) size_rectangle.left);
  (void) WriteBlobMSBShort(image,(unsigned short) size_rectangle.bottom);
  (void) WriteBlobMSBShort(image,(unsigned short) size_rectangle.right);
  (void) WriteBlobMSBShort(image,PictVersion);
  (void) WriteBlobMSBShort(image,0x02ff);  /* version #2 */
  (void) WriteBlobMSBShort(image,PictInfoOp);
  (void) WriteBlobMSBLong(image,0xFFFE0000UL);
  /*
    Write full size of the file, resolution, frame bounding box, and reserved.
  */
  (void) WriteBlobMSBShort(image,(unsigned short) x_resolution);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1767,7 +1767,16 @@
   if ((buffer == (unsigned char *) NULL) ||
       (packed_scanline == (unsigned char *) NULL) ||
       (scanline == (unsigned char *) NULL))
-    ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
+    {
+      if (scanline != (unsigned char *) NULL)
+        scanline=(unsigned char *) RelinquishMagickMemory(scanline);
+      if (packed_scanline != (unsigned char *) NULL)
+        packed_scanline=(unsigned char *) RelinquishMagickMemory(
+          packed_scanline);
+      if (buffer != (unsigned char *) NULL)
+        buffer=(unsigned char *) RelinquishMagickMemory(buffer);
+      ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
+    }
   (void) ResetMagickMemory(scanline,0,row_bytes);
   (void) ResetMagickMemory(packed_scanline,0,(size_t) (row_bytes+MaxCount));
   /*
```
