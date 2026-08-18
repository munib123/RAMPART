# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2613_1
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2613_1`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 4283-4323 of the vulnerable file.

    /*
      Read a new JNG chunk.
    */
    status=SetImageProgress(image,LoadImagesTag,TellBlob(image),
      2*GetBlobSize(image));

    if (status == MagickFalse)
      break;

    type[0]='\0';
    (void) ConcatenateMagickString(type,"errr",MaxTextExtent);
    length=ReadBlobMSBLong(image);
    count=(unsigned int) ReadBlob(image,4,(unsigned char *) type);

    if (logging != MagickFalse)
      (void) LogMagickEvent(CoderEvent,GetMagickModule(),
        "  Reading JNG chunk type %c%c%c%c, length: %.20g",
        type[0],type[1],type[2],type[3],(double) length);

    if (length > PNG_UINT_31_MAX || count == 0)
      ThrowReaderException(CorruptImageError,"CorruptImage");

    p=NULL;
    chunk=(unsigned char *) NULL;

    if (length != 0)
      {
        if (length > GetBlobSize(image))
          ThrowReaderException(CorruptImageError,"InsufficientImageDataInFile");
        chunk=(unsigned char *) AcquireQuantumMemory(length+MagickPathExtent,
          sizeof(*chunk));

        if (chunk == (unsigned char *) NULL)
          ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");

        for (i=0; i < (ssize_t) length; i++)
        {
          int
            c;

          c=ReadBlobByte(image);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4300,7 +4300,13 @@
         type[0],type[1],type[2],type[3],(double) length);
 
     if (length > PNG_UINT_31_MAX || count == 0)
-      ThrowReaderException(CorruptImageError,"CorruptImage");
+      {
+        if (color_image != (Image *) NULL)
+          color_image=DestroyImage(color_image);
+        if (color_image_info != (Image *) NULL)
+          color_image_info=DestroyImageInfo(color_image_info);
+        ThrowReaderException(CorruptImageError,"CorruptImage");
+      }
 
     p=NULL;
     chunk=(unsigned char *) NULL;
```
