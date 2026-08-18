# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2621_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2621_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 921-961 of the vulnerable file.

  if (!strncmp(MATLAB_HDR.EndianIndicator, "IM", 2))
  {
    ReadBlobXXXLong = ReadBlobLSBLong;
    ReadBlobXXXShort = ReadBlobLSBShort;
    ReadBlobDoublesXXX = ReadBlobDoublesLSB;
    ReadBlobFloatsXXX = ReadBlobFloatsLSB;
    image->endian = LSBEndian;
  }
  else if (!strncmp(MATLAB_HDR.EndianIndicator, "MI", 2))
  {
    ReadBlobXXXLong = ReadBlobMSBLong;
    ReadBlobXXXShort = ReadBlobMSBShort;
    ReadBlobDoublesXXX = ReadBlobDoublesMSB;
    ReadBlobFloatsXXX = ReadBlobFloatsMSB;
    image->endian = MSBEndian;
  }
  else
    goto MATLAB_KO;    /* unsupported endian */

  if (strncmp(MATLAB_HDR.identific, "MATLAB", 6))
MATLAB_KO: ThrowReaderException(CorruptImageError,"ImproperImageHeader");

  filepos = TellBlob(image);
  while(!EOFBlob(image)) /* object parser loop */
  {
    Frames = 1;
    (void) SeekBlob(image,filepos,SEEK_SET);
    /* printf("pos=%X\n",TellBlob(image)); */

    MATLAB_HDR.DataType = ReadBlobXXXLong(image);
    if(EOFBlob(image)) break;
    MATLAB_HDR.ObjectSize = ReadBlobXXXLong(image);
    if(EOFBlob(image)) break;
    if(MATLAB_HDR.ObjectSize+filepos > GetBlobSize(image))
      goto MATLAB_KO;
    filepos += MATLAB_HDR.ObjectSize + 4 + 4;

    clone_info=CloneImageInfo(image_info);
    image2 = image;
#if defined(MAGICKCORE_ZLIB_DELEGATE)
    if(MATLAB_HDR.DataType == miCOMPRESSED)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -938,7 +938,11 @@
     goto MATLAB_KO;    /* unsupported endian */
 
   if (strncmp(MATLAB_HDR.identific, "MATLAB", 6))
-MATLAB_KO: ThrowReaderException(CorruptImageError,"ImproperImageHeader");
+    {
+MATLAB_KO:
+      clone_info=DestroyImageInfo(clone_info);
+      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
+    }
 
   filepos = TellBlob(image);
   while(!EOFBlob(image)) /* object parser loop */
```
