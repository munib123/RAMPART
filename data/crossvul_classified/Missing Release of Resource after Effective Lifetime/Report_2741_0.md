# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2741_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2741_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 869-909 of the vulnerable file.

  int sample_size;
  MagickOffsetType filepos=0x80;
  BlobInfo *blob;
  size_t one;

  unsigned int (*ReadBlobXXXLong)(Image *image);
  unsigned short (*ReadBlobXXXShort)(Image *image);
  void (*ReadBlobDoublesXXX)(Image * image, size_t len, double *data);
  void (*ReadBlobFloatsXXX)(Image * image, size_t len, float *data);


  assert(image_info != (const ImageInfo *) NULL);
  assert(image_info->signature == MagickSignature);
  assert(exception != (ExceptionInfo *) NULL);
  assert(exception->signature == MagickSignature);
  logging = LogMagickEvent(CoderEvent,GetMagickModule(),"enter");

  /*
     Open image file.
   */
  image = AcquireImage(image_info);

  status = OpenBlob(image_info, image, ReadBinaryBlobMode, exception);
  if (status == MagickFalse)
    {
      image=DestroyImageList(image);
      return((Image *) NULL);
    }
  /*
     Read MATLAB image.
   */
  clone_info=CloneImageInfo(image_info);
  if(ReadBlob(image,124,(unsigned char *) &MATLAB_HDR.identific) != 124)
    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
  if (strncmp(MATLAB_HDR.identific,"MATLAB",6) != 0)
    {
      image2=ReadMATImageV4(image_info,image,exception);
      if (image2  == NULL)
        goto MATLAB_KO;
      image=image2;
      goto END_OF_READING;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -886,6 +886,7 @@
   /*
      Open image file.
    */
+  quantum_info=(QuantumInfo *) NULL;
   image = AcquireImage(image_info);
 
   status = OpenBlob(image_info, image, ReadBinaryBlobMode, exception);
@@ -1300,7 +1301,8 @@
   }
 
   RelinquishMagickMemory(BImgBuff);
-  quantum_info=DestroyQuantumInfo(quantum_info);
+  if (quantum_info != (QuantumInfo *) NULL)
+    quantum_info=DestroyQuantumInfo(quantum_info);
 END_OF_READING:
   clone_info=DestroyImageInfo(clone_info);
   CloseBlob(image);
```
