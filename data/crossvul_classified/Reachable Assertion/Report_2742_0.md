# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 2742_0
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2742_0`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 923-963 of the vulnerable file.

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
    {
MATLAB_KO:
      clone_info=DestroyImageInfo(clone_info);
      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
    }

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
    if((MagickSizeType) (MATLAB_HDR.ObjectSize+filepos) > GetBlobSize(image))
      goto MATLAB_KO;
    filepos += MATLAB_HDR.ObjectSize + 4 + 4;

    clone_info=CloneImageInfo(image_info);
    image2 = image;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -940,7 +940,8 @@
   if (strncmp(MATLAB_HDR.identific, "MATLAB", 6))
     {
 MATLAB_KO:
-      clone_info=DestroyImageInfo(clone_info);
+      if (clone_info != (ImageInfo *) NULL)
+        clone_info=DestroyImageInfo(clone_info);
       ThrowReaderException(CorruptImageError,"ImproperImageHeader");
     }
 
```
