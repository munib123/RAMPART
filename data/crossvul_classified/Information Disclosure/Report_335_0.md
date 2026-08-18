# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 335_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `335_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 338-378 of the vulnerable file.

  hex_digits[(int) '\t']=(-1);
  /*
    Read hex image data.
  */
  padding=0;
  if (((image->columns % 16) != 0) && ((image->columns % 16) < 9) &&
      (version == 10))
    padding=1;
  bytes_per_line=(unsigned int) (image->columns+7)/8+padding;
  length=(unsigned int) image->rows;
  data=(unsigned char *) AcquireQuantumMemory(length,bytes_per_line*
    sizeof(*data));
  if (data == (unsigned char *) NULL)
    ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
  p=data;
  if (version == 10)
    for (i=0; i < (ssize_t) (bytes_per_line*image->rows); (i+=2))
    {
      c=XBMInteger(image,hex_digits);
      if (c < 0)
        break;
      *p++=(unsigned char) c;
      if ((padding == 0) || (((i+2) % bytes_per_line) != 0))
        *p++=(unsigned char) (c >> 8);
    }
  else
    for (i=0; i < (ssize_t) (bytes_per_line*image->rows); i++)
    {
      c=XBMInteger(image,hex_digits);
      if (c < 0)
        break;
      *p++=(unsigned char) c;
    }
  if (EOFBlob(image) != MagickFalse)
    {
      data=(unsigned char *) RelinquishMagickMemory(data);
      ThrowReaderException(CorruptImageError,"UnexpectedEndOfFile");
    }
  /*
    Convert X bitmap image to pixel packets.
  */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -355,7 +355,10 @@
     {
       c=XBMInteger(image,hex_digits);
       if (c < 0)
-        break;
+        {
+          data=(unsigned char *) RelinquishMagickMemory(data);
+          ThrowReaderException(CorruptImageError,"ImproperImageHeader");
+        }
       *p++=(unsigned char) c;
       if ((padding == 0) || (((i+2) % bytes_per_line) != 0))
         *p++=(unsigned char) (c >> 8);
@@ -365,7 +368,10 @@
     {
       c=XBMInteger(image,hex_digits);
       if (c < 0)
-        break;
+        {
+          data=(unsigned char *) RelinquishMagickMemory(data);
+          ThrowReaderException(CorruptImageError,"ImproperImageHeader");
+        }
       *p++=(unsigned char) c;
     }
   if (EOFBlob(image) != MagickFalse)
```
