# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 138_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `138_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2019-2059 of the vulnerable file.

    int i = 0;
    if (i + 3 < data_size && data[i] == 0xFF && data[i+1] == 0xD8 &&
            data[i+2] == 0xFF && data[i+3] == 0xE0) {
        i += 4;
        if(i + 6 < data_size &&
                data[i+2] == 'J' && data[i+3] == 'F' && data[i+4] == 'I' &&
                data[i+5] == 'F' && data[i+6] == 0x00) {
            unsigned short block_length = data[i] * 256 + data[i+1];
            while(i<data_size) {
                i+=block_length;
                if((i + 1) >= data_size)
                    return -1;
                if(data[i] != 0xFF)
                    return -1;
                if(data[i+1] == 0xC0) {
                    *height = data[i+5]*256 + data[i+6];
                    *width = data[i+7]*256 + data[i+8];
                    return 0;
                }
                i+=2;
                block_length = data[i] * 256 + data[i+1];
            }
        }
    }

    return -1;
}

static pdf_object *pdf_add_raw_jpeg(struct pdf_doc *pdf,
                                    const char *jpeg_file)
{
    struct stat buf;
    off_t len;
    char *final_data;
    uint8_t *jpeg_data;
    int written = 0;
    FILE *fp;
    struct pdf_object *obj;
    int width, height;

    if (stat(jpeg_file, &buf) < 0) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2036,7 +2036,8 @@
                     return 0;
                 }
                 i+=2;
-                block_length = data[i] * 256 + data[i+1];
+                if (i + 1 < data_size)
+                    block_length = data[i] * 256 + data[i+1];
             }
         }
     }
```
