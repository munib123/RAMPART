# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5308_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5308_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 335-375 of the vulnerable file.

{
  ssize_t
    y;

  register ssize_t
    x;

  register Quantum
    *q;

  ssize_t
    count;

  unsigned char
    *graydata;

  XCFPixelInfo
    *xcfdata,
    *xcfodata;

  xcfdata=(XCFPixelInfo *) AcquireQuantumMemory(data_length,sizeof(*xcfdata));
  if (xcfdata == (XCFPixelInfo *) NULL)
    ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
      image->filename);
  xcfodata=xcfdata;
  graydata=(unsigned char *) xcfdata;  /* used by gray and indexed */
  count=ReadBlob(image,data_length,(unsigned char *) xcfdata);
  if (count != (ssize_t) data_length)
    ThrowBinaryException(CorruptImageError,"NotEnoughPixelData",
      image->filename);
  for (y=0; y < (ssize_t) tile_image->rows; y++)
  {
    q=GetAuthenticPixels(tile_image,0,y,tile_image->columns,1,exception);
    if (q == (Quantum *) NULL)
      break;
    if (inDocInfo->image_type == GIMP_GRAY)
      {
        for (x=0; x < (ssize_t) tile_image->columns; x++)
        {
          SetPixelGray(tile_image,ScaleCharToQuantum(*graydata),q);
          SetPixelAlpha(tile_image,ScaleCharToQuantum((unsigned char)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -352,7 +352,8 @@
     *xcfdata,
     *xcfodata;
 
-  xcfdata=(XCFPixelInfo *) AcquireQuantumMemory(data_length,sizeof(*xcfdata));
+  xcfdata=(XCFPixelInfo *) AcquireQuantumMemory(MagickMax(data_length,
+    tile_image->columns*tile_image->rows),sizeof(*xcfdata));
   if (xcfdata == (XCFPixelInfo *) NULL)
     ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
       image->filename);
```
