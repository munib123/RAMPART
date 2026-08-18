# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1414_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1414_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 2773-2813 of the vulnerable file.

    return(0);
  pixels=(unsigned char *) GetQuantumPixels(quantum_info);
#ifdef MAGICKCORE_ZLIB_DELEGATE
  if (compression == ZipCompression)
    {
      compressed_pixels=(unsigned char *) AcquireQuantumMemory(CHUNK,
        sizeof(*compressed_pixels));
      if (compressed_pixels == (unsigned char *) NULL)
        {
          quantum_info=DestroyQuantumInfo(quantum_info);
          return(0);
        }
      memset(&stream,0,sizeof(stream));
      stream.data_type=Z_BINARY;
      level=Z_DEFAULT_COMPRESSION;
      if ((image_info->quality > 0 && image_info->quality < 10))
        level=(int) image_info->quality;
      if (deflateInit(&stream,level) != Z_OK)
        {
          quantum_info=DestroyQuantumInfo(quantum_info);
          return(0);
        }
    }
#endif
  for (y=0; y < (ssize_t) next_image->rows; y++)
  {
    p=GetVirtualPixels(next_image,0,y,next_image->columns,1,exception);
    if (p == (const Quantum *) NULL)
      break;
    length=ExportQuantumPixels(next_image,(CacheView *) NULL,quantum_info,
      quantum_type,pixels,exception);
    if (monochrome != MagickFalse)
      for (i=0; i < (ssize_t) length; i++)
        pixels[i]=(~pixels[i]);
    if (compression == RLECompression)
      {
        length=PSDPackbitsEncodeImage(image,length,pixels,compact_pixels,
          exception);
        count+=WriteBlob(image,length,compact_pixels);
        size_offset+=WritePSDOffset(psd_info,image,length,size_offset);
      }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2790,6 +2790,8 @@
       if (deflateInit(&stream,level) != Z_OK)
         {
           quantum_info=DestroyQuantumInfo(quantum_info);
+          compressed_pixels=(unsigned char *) RelinquishMagickMemory(
+            compressed_pixels);
           return(0);
         }
     }
```
