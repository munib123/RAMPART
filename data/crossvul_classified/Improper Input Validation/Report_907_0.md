# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 907_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `907_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 555-595 of the vulnerable file.

      image->colors=256;
      if (AcquireImageColormap(image,image->colors) == MagickFalse)
        {
        NoMemory:
          ThrowCUTReaderException(ResourceLimitError,"MemoryAllocationFailed");
            }

      for (i=0; i < (ssize_t)image->colors; i++)
        {
          image->colormap[i].red=ScaleCharToQuantum((unsigned char) i);
          image->colormap[i].green=ScaleCharToQuantum((unsigned char) i);
          image->colormap[i].blue=ScaleCharToQuantum((unsigned char) i);
        }
    }


  /* ----- Load RLE compressed raster ----- */
  BImgBuff=(unsigned char *) AcquireQuantumMemory((size_t) ldblk,
    sizeof(*BImgBuff));  /*Ldblk was set in the check phase*/
  if(BImgBuff==NULL) goto NoMemory;

  offset=SeekBlob(image,6 /*sizeof(Header)*/,SEEK_SET);
  if (offset < 0)
    {
      if (palette != NULL)
        palette=DestroyImage(palette);
      if (clone_info != NULL)
        clone_info=DestroyImageInfo(clone_info);
      BImgBuff=(unsigned char *) RelinquishMagickMemory(BImgBuff);
      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
    }
  for (i=0; i < (int) Header.Height; i++)
  {
      EncodedByte=ReadBlobLSBShort(image);

      ptrB=BImgBuff;
      j=ldblk;

      RunCount=(unsigned char) ReadBlobByte(image);
      RunCountMasked=RunCount & 0x7F;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -572,6 +572,7 @@
   BImgBuff=(unsigned char *) AcquireQuantumMemory((size_t) ldblk,
     sizeof(*BImgBuff));  /*Ldblk was set in the check phase*/
   if(BImgBuff==NULL) goto NoMemory;
+  (void) memset(BImgBuff,0,(size_t) ldblk*sizeof(*BImgBuff));
 
   offset=SeekBlob(image,6 /*sizeof(Header)*/,SEEK_SET);
   if (offset < 0)
```
