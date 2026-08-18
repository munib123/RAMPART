# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 361_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `361_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 4550-4590 of the vulnerable file.

        DestroyJNG(NULL,&color_image,&color_image_info,
          &alpha_image,&alpha_image_info);
        ThrowReaderException(CorruptImageError,"ImproperImageHeader");
      }
    if (length > GetBlobSize(image))
      {
        DestroyJNG(NULL,&color_image,&color_image_info,
          &alpha_image,&alpha_image_info);
        ThrowReaderException(CorruptImageError,
          "InsufficientImageDataInFile");
      }

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
          if (c == EOF)
            break;
          chunk[i]=(unsigned char) c;
        }
        for ( ; i < (ssize_t) length; i++)
          chunk[i]='\0';

        p=chunk;
      }

    (void) ReadBlobMSBLong(image);  /* read crc word */

    if (memcmp(type,mng_JHDR,4) == 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4567,7 +4567,11 @@
         chunk=(unsigned char *) AcquireQuantumMemory(length,sizeof(*chunk));
 
         if (chunk == (unsigned char *) NULL)
-          ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+          {
+            DestroyJNG(NULL,&color_image,&color_image_info,
+              &alpha_image,&alpha_image_info);
+            ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+          }
 
         for (i=0; i < (ssize_t) length; i++)
         {
@@ -4594,13 +4598,12 @@
             jng_width=(png_uint_32)mng_get_long(p);
             jng_height=(png_uint_32)mng_get_long(&p[4]);
             if ((jng_width == 0) || (jng_height == 0))
-            {
-              DestroyJNG(chunk,&color_image,&color_image_info,
-                &alpha_image,&alpha_image_info);
-
-              ThrowReaderException(CorruptImageError,
-                "NegativeOrZeroImageSize");
-            }
+              {
+                DestroyJNG(chunk,&color_image,&color_image_info,
+                  &alpha_image,&alpha_image_info);
+                ThrowReaderException(CorruptImageError,
+                  "NegativeOrZeroImageSize");
+              }
             jng_color_type=p[8];
             jng_image_sample_depth=p[9];
             jng_image_compression_method=p[10];
```
