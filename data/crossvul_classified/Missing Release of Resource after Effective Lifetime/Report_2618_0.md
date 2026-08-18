# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2618_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2618_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 270-310 of the vulnerable file.

    bits_per_pixel,
    version,
    nextDepthOffset,
    transparentIndex,
    compressionType,
    byte,
    mask,
    redbits,
    greenbits,
    bluebits,
    one,
    pad,
    size,
    bit;

  ssize_t
    count,
    y;

  unsigned char
    *lastrow,
    *one_row,
    *ptr;

  unsigned short
    color16;

  /*
    Open image file.
  */
  assert(image_info != (const ImageInfo *) NULL);
  assert(image_info->signature == MagickSignature);
  if (image_info->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",
      image_info->filename);
  assert(exception != (ExceptionInfo *) NULL);
  assert(exception->signature == MagickSignature);
  image=AcquireImage(image_info);
  status=OpenBlob(image_info,image,ReadBinaryBlobMode,exception);
  if (status == MagickFalse)
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -287,7 +287,7 @@
     y;
 
   unsigned char
-    *lastrow,
+    *last_row,
     *one_row,
     *ptr;
 
@@ -423,12 +423,12 @@
       2*image->columns),sizeof(*one_row));
     if (one_row == (unsigned char *) NULL)
       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
-    lastrow=(unsigned char *) NULL;
+    last_row=(unsigned char *) NULL;
     if (compressionType == PALM_COMPRESSION_SCANLINE)
       {
-        lastrow=(unsigned char *) AcquireQuantumMemory(MagickMax(bytes_per_row,
-          2*image->columns),sizeof(*lastrow));
-        if (lastrow == (unsigned char *) NULL)
+        last_row=(unsigned char *) AcquireQuantumMemory(MagickMax(bytes_per_row,
+          2*image->columns),sizeof(*last_row));
+        if (last_row == (unsigned char *) NULL)
           ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
       }
     mask=(size_t) (1U << bits_per_pixel)-1;
@@ -479,10 +479,10 @@
                   if ((y == 0) || (count & (one << (7 - bit))))
                     one_row[i+bit]=(unsigned char) ReadBlobByte(image);
                   else
-                    one_row[i+bit]=lastrow[i+bit];
+                    one_row[i+bit]=last_row[i+bit];
                 }
               }
-              (void) CopyMagickMemory(lastrow, one_row, bytes_per_row);
+              (void) CopyMagickMemory(last_row, one_row, bytes_per_row);
             }
         }
       ptr=one_row;
@@ -496,7 +496,7 @@
             {
               one_row=(unsigned char *) RelinquishMagickMemory(one_row);
               if (compressionType == PALM_COMPRESSION_SCANLINE)
-                lastrow=(unsigned char *) RelinquishMagickMemory(lastrow);
+                last_row=(unsigned char *) RelinquishMagickMemory(last_row);
               ThrowReaderException(CorruptImageError,"CorruptImage");
             }
           for (x=0; x < (ssize_t) image->columns; x++)
@@ -519,7 +519,7 @@
               {
                 one_row=(unsigned char *) RelinquishMagickMemory(one_row);
                 if (compressionType == PALM_COMPRESSION_SCANLINE)
-                  lastrow=(unsigned char *) RelinquishMagickMemory(lastrow);
+                  last_row=(unsigned char *) RelinquishMagickMemory(last_row);
                 ThrowReaderException(CorruptImageError,"CorruptImage");
               }
             index=(IndexPacket) (mask-(((*ptr) & (mask << bit)) >> bit));
@@ -556,7 +556,7 @@
       }
     one_row=(unsigned char *) RelinquishMagickMemory(one_row);
     if (compressionType == PALM_COMPRESSION_SCANLINE)
-      lastrow=(unsigned char *) RelinquishMagickMemory(lastrow);
+      last_row=(unsigned char *) RelinquishMagickMemory(last_row);
     if (EOFBlob(image) != MagickFalse)
       {
         ThrowFileException(exception,CorruptImageError,"UnexpectedEndOfFile",
@@ -736,7 +736,7 @@
     bit,
     byte,
     color,
-    *lastrow,
+    *last_row,
     *one_row,
     *ptr,
     version;
@@ -873,15 +873,24 @@
       }
     if (flags & PALM_IS_COMPRESSED_FLAG)
       (void) WriteBlobMSBShort(image,0);  /* fill in size later */
-    lastrow=(unsigned char *) NULL;
+    last_row=(unsigned char *) NULL;
     if (image_info->compression == FaxCompression)
-      lastrow=(unsigned char *) AcquireQuantumMemory(bytes_per_row,
-        sizeof(*lastrow));
-      /* TODO check whether memory really was acquired? */
+      {
+        last_row=(unsigned char *) AcquireQuantumMemory(bytes_per_row,
+          sizeof(*last_row));
+        if (last_row == (unsigned char *) NULL)
+          {
+            quantize_info=DestroyQuantizeInfo(quantize_info);
+            ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
+          }
+      }
     one_row=(unsigned char *) AcquireQuantumMemory(bytes_per_row,
       sizeof(*one_row));
     if (one_row == (unsigned char *) NULL)
-      ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
+      {
+        quantize_info=DestroyQuantizeInfo(quantize_info);
+        ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
+      }
     for (y=0; y < (ssize_t) image->rows; y++)
     {
       ptr=one_row;
@@ -961,7 +970,7 @@
               tptr = tmpbuf;
               for (bit=0, byte=0; bit < (unsigned char) MagickMin(8,(ssize_t) bytes_per_row-x); bit++)
               {
-                if ((y == 0) || (lastrow[x + bit] != one_row[x + bit]))
+                if ((y == 0) || (last_row[x + bit] != one_row[x + bit]))
                   {
                     byte |= (1 << (7 - bit));
                     *tptr++ = (char) one_row[x + bit];
@@ -970,7 +979,7 @@
               (void) WriteBlobByte(image, byte);
               (void) WriteBlob(image,tptr-tmpbuf,(unsigned char *) tmpbuf);
             }
-            (void) CopyMagickMemory(lastrow,one_row,bytes_per_row);
+            (void) CopyMagickMemory(last_row,one_row,bytes_per_row);
           }
         else
           (void) WriteBlob(image,bytes_per_row,one_row);
@@ -986,9 +995,12 @@
       {
         offset=SeekBlob(image,currentOffset+20,SEEK_SET);
         (void) WriteBlobByte(image,0);  /* reserved by Palm */
-        (void) WriteBlobByte(image,(unsigned char) ((31*transpix.red)/QuantumRange));
-        (void) WriteBlobByte(image,(unsigned char) ((63*transpix.green)/QuantumRange));
-        (void) WriteBlobByte(image,(unsigned char) ((31*transpix.blue)/QuantumRange));
+        (void) WriteBlobByte(image,(unsigned char) ((31*transpix.red)/
+          QuantumRange));
+        (void) WriteBlobByte(image,(unsigned char) ((63*transpix.green)/
+          QuantumRange));
+        (void) WriteBlobByte(image,(unsigned char) ((31*transpix.blue)/
+          QuantumRange));
       }
     if (flags & PALM_IS_COMPRESSED_FLAG)  /* fill in size now */
       {
@@ -998,8 +1010,8 @@
       }
     if (one_row != (unsigned char *) NULL)
       one_row=(unsigned char *) RelinquishMagickMemory(one_row);
-    if (lastrow != (unsigned char *) NULL)
-      lastrow=(unsigned char *) RelinquishMagickMemory(lastrow);
+    if (last_row != (unsigned char *) NULL)
+      last_row=(unsigned char *) RelinquishMagickMemory(last_row);
     if (GetNextImageInList(image) == (Image *) NULL)
       break;
     /* padding to 4 byte word */
```
