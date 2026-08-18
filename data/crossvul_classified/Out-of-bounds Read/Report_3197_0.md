# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3197_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3197_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 446-486 of the vulnerable file.

        ((bytes_per_line/sun_info.depth) != sun_info.width))
      {
        sun_data=(unsigned char *) RelinquishMagickMemory(sun_data);
        ThrowReaderException(ResourceLimitError,"ImproperImageHeader");
      }
    quantum=sun_info.depth == 1 ? 15 : 7;
    bytes_per_line+=quantum;
    bytes_per_line<<=1;
    if ((bytes_per_line >> 1) != (sun_info.width*sun_info.depth+quantum))
      {
        sun_data=(unsigned char *) RelinquishMagickMemory(sun_data);
        ThrowReaderException(ResourceLimitError,"ImproperImageHeader");
      }
    bytes_per_line>>=4;
    if (HeapOverflowSanityCheck(height,bytes_per_line) != MagickFalse)
      {
        sun_data=(unsigned char *) RelinquishMagickMemory(sun_data);
        ThrowReaderException(ResourceLimitError,"ImproperImageHeader");
      }
    pixels_length=height*bytes_per_line;
    sun_pixels=(unsigned char *) AcquireQuantumMemory(pixels_length,
      sizeof(*sun_pixels));
    if (sun_pixels == (unsigned char *) NULL)
      {
        sun_data=(unsigned char *) RelinquishMagickMemory(sun_data);
        ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
      }
    ResetMagickMemory(sun_pixels,0,pixels_length*sizeof(*sun_pixels));
    if (sun_info.type == RT_ENCODED)
      {
        status=DecodeImage(sun_data,sun_info.length,sun_pixels,pixels_length);
        if (status == MagickFalse)
          ThrowReaderException(CorruptImageError,"UnableToReadImageData");
      }
    else
      {
        if (sun_info.length > pixels_length)
          {
            sun_data=(unsigned char *) RelinquishMagickMemory(sun_data);
            sun_pixels=(unsigned char *) RelinquishMagickMemory(sun_pixels);
            ThrowReaderException(ResourceLimitError,"ImproperImageHeader");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -463,7 +463,7 @@
         ThrowReaderException(ResourceLimitError,"ImproperImageHeader");
       }
     pixels_length=height*bytes_per_line;
-    sun_pixels=(unsigned char *) AcquireQuantumMemory(pixels_length,
+    sun_pixels=(unsigned char *) AcquireQuantumMemory(pixels_length+image->rows,
       sizeof(*sun_pixels));
     if (sun_pixels == (unsigned char *) NULL)
       {
```
