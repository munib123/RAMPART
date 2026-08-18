# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5009_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5009_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 950-978 of the vulnerable file.

            adjustR = (int)image->comps[0].prec - 8;
            printf("BMP CONVERSION: Truncating component 0 from %d bits to 8 bits\n", image->comps[0].prec);
        }else
            adjustR = 0;

        for (i = 0; i < 256; i++) {
            fprintf(fdest, "%c%c%c%c", i, i, i, 0);
        }

        for (i = 0; i < w * h; i++) {
            int r;

            r = image->comps[0].data[w * h - ((i) / (w) + 1) * w + (i) % (w)];
            r += (image->comps[0].sgnd ? 1 << (image->comps[0].prec - 1) : 0);
            r = ((r >> adjustR)+((r >> (adjustR-1))%2));
            if(r > 255) r = 255; else if(r < 0) r = 0;

            fprintf(fdest, "%c", (OPJ_UINT8)r);

            if ((i + 1) % w == 0) {
                for ((pad = w % 4) ? (4 - w % 4) : 0; pad > 0; pad--)	/* ADD */
                    fprintf(fdest, "%c", 0);
            }
        }
        fclose(fdest);
    }

    return 0;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -967,7 +967,7 @@
             fprintf(fdest, "%c", (OPJ_UINT8)r);
 
             if ((i + 1) % w == 0) {
-                for ((pad = w % 4) ? (4 - w % 4) : 0; pad > 0; pad--)	/* ADD */
+                for (pad = (w % 4) ? (4 - w % 4) : 0; pad > 0; pad--)	/* ADD */
                     fprintf(fdest, "%c", 0);
             }
         }
```
