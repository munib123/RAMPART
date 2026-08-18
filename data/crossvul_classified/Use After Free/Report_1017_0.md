# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1017_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1017_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 626-666 of the vulnerable file.


  ssize_t
    count,
    y;

  unsigned char
    *pixels;

  unsigned int
    depth;

  quantum_info=(QuantumInfo *) NULL;
  (void) SeekBlob(image,0,SEEK_SET);
  status=MagickTrue;
  while (EOFBlob(image) == MagickFalse)
  {
    /*
     Object parser loop.
    */
    ldblk=ReadBlobLSBLong(image);
    if ((ldblk > 9999) || (ldblk < 0))
      break;
    HDR.Type[3]=ldblk % 10; ldblk /= 10;  /* T digit */
    HDR.Type[2]=ldblk % 10; ldblk /= 10;  /* P digit */
    HDR.Type[1]=ldblk % 10; ldblk /= 10;  /* O digit */
    HDR.Type[0]=ldblk;        /* M digit */
    if (HDR.Type[3] != 0)
      break;  /* Data format */
    if (HDR.Type[2] != 0)
      break;  /* Always 0 */
    if (HDR.Type[0] == 0)
      {
        HDR.nRows=ReadBlobLSBLong(image);
        HDR.nCols=ReadBlobLSBLong(image);
        HDR.imagf=ReadBlobLSBLong(image);
        HDR.nameLen=ReadBlobLSBLong(image);
        endian=LSBEndian;
      }
    else
      {
        HDR.nRows=ReadBlobMSBLong(image);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -643,6 +643,7 @@
      Object parser loop.
     */
     ldblk=ReadBlobLSBLong(image);
+    if(EOFBlob(image)) break;
     if ((ldblk > 9999) || (ldblk < 0))
       break;
     HDR.Type[3]=ldblk % 10; ldblk /= 10;  /* T digit */
@@ -964,10 +965,10 @@
     }
 
   filepos = TellBlob(image);
-  while(!EOFBlob(image)) /* object parser loop */
+  while(filepos < GetBlobSize(image) && !EOFBlob(image)) /* object parser loop */
   {
     Frames = 1;
-    if (filepos != (unsigned int) filepos)
+    if(filepos > GetBlobSize(image) || filepos < 0)
       break;
     if(SeekBlob(image,filepos,SEEK_SET) != filepos) break;
     /* printf("pos=%X\n",TellBlob(image)); */
@@ -976,7 +977,7 @@
     if(EOFBlob(image)) break;
     MATLAB_HDR.ObjectSize = ReadBlobXXXLong(image);
     if(EOFBlob(image)) break;
-    if((MagickSizeType) (MATLAB_HDR.ObjectSize+filepos) > GetBlobSize(image))
+    if((MagickSizeType) (MATLAB_HDR.ObjectSize+filepos) >= GetBlobSize(image))
       goto MATLAB_KO;
     filepos += (MagickOffsetType) MATLAB_HDR.ObjectSize + 4 + 4;
 
@@ -1279,6 +1280,7 @@
           {
             if (logging) (void)LogMagickEvent(CoderEvent,GetMagickModule(),
               "  MAT cannot read scanrow %u from a file.", (unsigned)(MATLAB_HDR.SizeY-i-1));
+            ThrowReaderException(CorruptImageError,"UnexpectedEndOfFile");
             goto ExitLoop;
           }
         if((CellType==miINT8 || CellType==miUINT8) && (MATLAB_HDR.StructureFlag & FLAG_LOGICAL))
```
