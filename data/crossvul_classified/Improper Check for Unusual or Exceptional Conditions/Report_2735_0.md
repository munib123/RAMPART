# CrossVul Fix Pair: Improper Check for Unusual or Exceptional Conditions in c
**Pair ID:** 2735_0
**Vulnerability Class:** Improper Check for Unusual or Exceptional Conditions
**CWE:** CWE-754
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2735_0`)

## Vulnerability Information & PoC

## Description
Improper Check for Unusual or Exceptional Conditions - The programmer may assume that certain events or conditions will never occur or do not need to be worried about, such as low memory conditions, lack of access to resources due to restrictive permis...

## Vulnerable Code
```c
Lines 4295-4335 of the vulnerable file.


    if (length > PNG_UINT_31_MAX || count == 0)
      ThrowReaderException(CorruptImageError,"CorruptImage");

    p=NULL;
    chunk=(unsigned char *) NULL;

    if (length != 0)
      {
        chunk=(unsigned char *) AcquireQuantumMemory(length,sizeof(*chunk));

        if (chunk == (unsigned char *) NULL)
          ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");

        for (i=0; i < (ssize_t) length; i++)
        {
          int
            c;

          c=ReadBlobByte(image);
          chunk[i]=(unsigned char) c;
        }

        p=chunk;
      }

    (void) ReadBlobMSBLong(image);  /* read crc word */

    if (memcmp(type,mng_JHDR,4) == 0)
      {
        if (length == 16)
          {
            jng_width=(size_t) ((p[0] << 24) | (p[1] << 16) |
              (p[2] << 8) | p[3]);
            jng_height=(size_t) ((p[4] << 24) | (p[5] << 16) |
              (p[6] << 8) | p[7]);
            if ((jng_width == 0) || (jng_height == 0))
              ThrowReaderException(CorruptImageError,"NegativeOrZeroImageSize");
            jng_color_type=p[8];
            jng_image_sample_depth=p[9];
            jng_image_compression_method=p[10];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4312,6 +4312,8 @@
             c;
 
           c=ReadBlobByte(image);
+          if (c == EOF)
+            break;
           chunk[i]=(unsigned char) c;
         }
 
@@ -5171,6 +5173,8 @@
                 c;
 
               c=ReadBlobByte(image);
+              if (c == EOF)
+                break;
               chunk[i]=(unsigned char) c;
             }
 
```
