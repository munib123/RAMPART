# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3419_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3419_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 243-283 of the vulnerable file.

        return ret;

    while (x < 16) {
        cnt_x = pixel->lookup[x];
        if (value >= cumfr + cnt_x)
            cumfr += cnt_x;
        else
            break;
        x++;
    }

    c = x * 16;
    cnt_c = 0;
    while (c < 256) {
        cnt_c = pixel->freq[c];
        if (value >= cumfr + cnt_c)
            cumfr += cnt_c;
        else
            break;
        c++;
    }

    if ((ret = s->decode(gb, rc, cumfr, cnt_c, totfr)) < 0)
        return ret;

    pixel->freq[c] = cnt_c + step;
    pixel->lookup[x] = cnt_x + step;
    totfr += step;
    if (totfr > BOT) {
        totfr = 0;
        for (i = 0; i < 256; i++) {
            unsigned nc = (pixel->freq[i] >> 1) + 1;
            pixel->freq[i] = nc;
            totfr += nc;
        }
        for (i = 0; i < 16; i++) {
            unsigned sum = 0;
            unsigned i16_17 = i << 4;
            for (j = 0; j < 16; j++)
                sum += pixel->freq[i16_17 + j];
            pixel->lookup[i] = sum;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -260,6 +260,9 @@
         else
             break;
         c++;
+    }
+    if (x >= 16 || c >= 256) {
+        return AVERROR_INVALIDDATA;
     }
 
     if ((ret = s->decode(gb, rc, cumfr, cnt_c, totfr)) < 0)
```
