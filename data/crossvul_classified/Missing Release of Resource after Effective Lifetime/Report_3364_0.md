# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 3364_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3364_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 167-207 of the vulnerable file.

  /*
    Convert bi-level image to pixel packets.
  */
  SetImageColorspace(image,GRAYColorspace);
  quantum_type=IndexQuantum;
  quantum_info=AcquireQuantumInfo(image_info,image);
  if (quantum_info == (QuantumInfo *) NULL)
    ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
  length=GetQuantumExtent(image,quantum_info,quantum_type);
  for (y=0; y < (ssize_t) image->rows; y++)
  {
    register PixelPacket
      *magick_restrict q;

    q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
    if (q == (PixelPacket *) NULL)
      break;
    pixels=(const unsigned char *) ReadBlobStream(image,length,
      GetQuantumPixels(quantum_info),&count);
    if (count != (ssize_t) length)
      ThrowReaderException(CorruptImageError,"UnableToReadImageData");
    (void) ImportQuantumPixels(image,(CacheView *) NULL,quantum_info,
      quantum_type,pixels,exception);
    (void) ReadBlobStream(image,(size_t) (-(ssize_t) length) & 0x01,
      GetQuantumPixels(quantum_info),&count);
    if (SyncAuthenticPixels(image,exception) == MagickFalse)
      break;
    status=SetImageProgress(image,LoadImageTag,(MagickOffsetType) y,
      image->rows);
    if (status == MagickFalse)
      break;
  }
  SetQuantumImageType(image,quantum_type);
  quantum_info=DestroyQuantumInfo(quantum_info);
  if (EOFBlob(image) != MagickFalse)
    ThrowFileException(exception,CorruptImageError,"UnexpectedEndOfFile",
      image->filename);
  (void) CloseBlob(image);
  return(GetFirstImageInList(image));
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -184,7 +184,10 @@
     pixels=(const unsigned char *) ReadBlobStream(image,length,
       GetQuantumPixels(quantum_info),&count);
     if (count != (ssize_t) length)
-      ThrowReaderException(CorruptImageError,"UnableToReadImageData");
+      {
+        quantum_info=DestroyQuantumInfo(quantum_info);
+        ThrowReaderException(CorruptImageError,"UnableToReadImageData");
+      }
     (void) ImportQuantumPixels(image,(CacheView *) NULL,quantum_info,
       quantum_type,pixels,exception);
     (void) ReadBlobStream(image,(size_t) (-(ssize_t) length) & 0x01,
```
