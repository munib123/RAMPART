# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3108_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3108_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 2475-2515 of the vulnerable file.


  unsigned char
    *compressed_pixels;

  z_stream
    stream;

  compressed_pixels=(unsigned char *) NULL;
  flush=Z_NO_FLUSH;
#endif
  count=0;
  if (separate != MagickFalse)
    {
      size_offset=TellBlob(image)+2;
      count+=WriteCompressionStart(psd_info,image,next_image,1);
    }
  if (next_image->depth > 8)
    next_image->depth=16;
  monochrome=IsMonochromeImage(image,&image->exception) && (image->depth == 1)
    ? MagickTrue : MagickFalse;
  quantum_info=AcquireQuantumInfo(image_info,image);
  if (quantum_info == (QuantumInfo *) NULL)
    return(0);
  pixels=GetQuantumPixels(quantum_info);
#ifdef MAGICKCORE_ZLIB_DELEGATE
  if (next_image->compression == ZipCompression)
    {
      compressed_pixels=(unsigned char *) AcquireQuantumMemory(CHUNK,
        sizeof(*compressed_pixels));
      if (compressed_pixels == (unsigned char *) NULL)
        {
          quantum_info=DestroyQuantumInfo(quantum_info);
          return(0);
        }
      ResetMagickMemory(&stream,0,sizeof(stream));
      stream.data_type=Z_BINARY;
      level=Z_DEFAULT_COMPRESSION;
      if ((image_info->quality > 0 && image_info->quality < 10))
        level=(int) image_info->quality;
      if (deflateInit(&stream,level) != Z_OK)
        {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2492,7 +2492,7 @@
     next_image->depth=16;
   monochrome=IsMonochromeImage(image,&image->exception) && (image->depth == 1)
     ? MagickTrue : MagickFalse;
-  quantum_info=AcquireQuantumInfo(image_info,image);
+  quantum_info=AcquireQuantumInfo(image_info,next_image);
   if (quantum_info == (QuantumInfo *) NULL)
     return(0);
   pixels=GetQuantumPixels(quantum_info);
```
