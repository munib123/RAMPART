# CrossVul Fix Pair: Off-by-one Error in c
**Pair ID:** 2801_0
**Vulnerability Class:** Off-by-one Error
**CWE:** CWE-193
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2801_0`)

## Vulnerability Information & PoC

## Description
Off-by-one Error - A product calculates or uses an incorrect maximum or minimum value that is 1 more, or 1 less, than the correct value.

## Vulnerable Code
```c
Lines 1479-1519 of the vulnerable file.

              high = (char)highbyte;
            } else
              extra = high = 0;
            length = (length & 0x7f) + 2;
            while (length && filename_size < fn_end) {
              unsigned cp = filename_size >> 1;
              filename[filename_size++] = high;
              filename[filename_size++] = p[cp] + extra;
              length--;
            }
          }
          break;
        }
      }
      if (filename_size > fn_end) {
        archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
          "Invalid filename");
        return (ARCHIVE_FATAL);
      }
      filename[filename_size++] = '\0';
      filename[filename_size++] = '\0';

      /* Decoded unicode form is UTF-16BE, so we have to update a string
       * conversion object for it. */
      if (rar->sconv_utf16be == NULL) {
        rar->sconv_utf16be = archive_string_conversion_from_charset(
           &a->archive, "UTF-16BE", 1);
        if (rar->sconv_utf16be == NULL)
          return (ARCHIVE_FATAL);
      }
      fn_sconv = rar->sconv_utf16be;

      strp = filename;
      while (memcmp(strp, "\x00\x00", 2))
      {
        if (!memcmp(strp, "\x00\\", 2))
          *(strp + 1) = '/';
        strp += 2;
      }
      p += offset;
    } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1496,7 +1496,11 @@
         return (ARCHIVE_FATAL);
       }
       filename[filename_size++] = '\0';
-      filename[filename_size++] = '\0';
+      /*
+       * Do not increment filename_size here as the computations below
+       * add the space for the terminating NUL explicitly.
+       */
+      filename[filename_size] = '\0';
 
       /* Decoded unicode form is UTF-16BE, so we have to update a string
        * conversion object for it. */
```
