# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 3363_0
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3363_0`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 4467-4508 of the vulnerable file.

                data[12]=jng_alpha_sample_depth;
                data[13]=0; /* color_type gray */
                data[14]=0; /* compression method 0 */
                data[15]=0; /* filter_method 0 */
                data[16]=0; /* interlace_method 0 */
                (void) WriteBlob(alpha_image,17,data);
                (void) WriteBlobMSBULong(alpha_image,crc32(0,data,17));
              }
          }
        reading_idat=MagickTrue;
      }

    if (memcmp(type,mng_JDAT,4) == 0)
      {
        /* Copy chunk to color_image->blob */

        if (logging != MagickFalse)
          (void) LogMagickEvent(CoderEvent,GetMagickModule(),
            "    Copying JDAT chunk data to color_blob.");

        (void) WriteBlob(color_image,length,chunk);

        if (length != 0)
          chunk=(unsigned char *) RelinquishMagickMemory(chunk);

        continue;
      }

    if (memcmp(type,mng_IDAT,4) == 0)
      {
        png_byte
           data[5];

        /* Copy IDAT header and chunk data to alpha_image->blob */

        if (alpha_image != NULL && image_info->ping == MagickFalse)
          {
            if (logging != MagickFalse)
              (void) LogMagickEvent(CoderEvent,GetMagickModule(),
                "    Copying IDAT chunk data to alpha_blob.");

            (void) WriteBlobMSBULong(alpha_image,(size_t) length);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4484,10 +4484,11 @@
           (void) LogMagickEvent(CoderEvent,GetMagickModule(),
             "    Copying JDAT chunk data to color_blob.");
 
-        (void) WriteBlob(color_image,length,chunk);
-
         if (length != 0)
-          chunk=(unsigned char *) RelinquishMagickMemory(chunk);
+          {
+            (void) WriteBlob(color_image,length,chunk);
+            chunk=(unsigned char *) RelinquishMagickMemory(chunk);
+          }
 
         continue;
       }
```
