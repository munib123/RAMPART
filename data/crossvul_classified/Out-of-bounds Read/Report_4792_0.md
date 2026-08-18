# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4792_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4792_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 861-901 of the vulnerable file.


    /*
      If ping is true, then only set image size and colors without
      reading any image data.
    */
    if (image_info->ping)
    {
      size_t temp = image->columns;
      image->columns = image->rows;
      image->rows = temp;
      goto done_reading; /* !!!!!! BAD  !!!! */
    }
    status=SetImageExtent(image,image->columns,image->rows);
    if (status == MagickFalse)
      {
        InheritException(exception,&image->exception);
        return(DestroyImageList(image));
      }

  /* ----- Load raster data ----- */
    BImgBuff = (unsigned char *) AcquireQuantumMemory((size_t) (ldblk),sizeof(unsigned char));    /* Ldblk was set in the check phase */
    if (BImgBuff == NULL)
      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");

    MinVal = 0;
    MaxVal = 0;
    if (CellType==miDOUBLE || CellType==miSINGLE)        /* Find Min and Max Values for floats */
    {
      CalcMinMax(image2, image_info->endian,  MATLAB_HDR.SizeX, MATLAB_HDR.SizeY, CellType, ldblk, BImgBuff, &quantum_info->minimum, &quantum_info->maximum);
    }

    /* Main loop for reading all scanlines */
    if(z==1) z=0; /* read grey scanlines */
    /* else read color scanlines */
    do
    {
      for (i = 0; i < (ssize_t) MATLAB_HDR.SizeY; i++)
      {
        q=GetAuthenticPixels(image,0,MATLAB_HDR.SizeY-i-1,image->columns,1,exception);
        if (q == (PixelPacket *) NULL)
  {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -878,7 +878,7 @@
       }
 
   /* ----- Load raster data ----- */
-    BImgBuff = (unsigned char *) AcquireQuantumMemory((size_t) (ldblk),sizeof(unsigned char));    /* Ldblk was set in the check phase */
+    BImgBuff = (unsigned char *) AcquireQuantumMemory((size_t) (ldblk),sizeof(double));    /* Ldblk was set in the check phase */
     if (BImgBuff == NULL)
       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
 
```
