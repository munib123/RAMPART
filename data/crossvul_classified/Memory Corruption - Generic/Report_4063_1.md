# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4063_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4063_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 207-247 of the vulnerable file.

    int thex,they,thew,theh;                                                    \
    int numsubs = 0;                                                            \
    int newLen;                                                                 \
    int nSubrectsUblen;                                                         \
                                                                                \
    nSubrectsUblen = cl->ublen;                                                 \
    cl->ublen++;                                                                \
    rfbStatRecordEncodingSentAdd(cl, rfbEncodingHextile, 1);                    \
                                                                                \
    for (y=0; y<h; y++) {                                                       \
        line = data+(y*w);                                                      \
        for (x=0; x<w; x++) {                                                   \
            if (line[x] != bg) {                                                \
                cl2 = line[x];                                                  \
                hy = y-1;                                                       \
                hyflag = 1;                                                     \
                for (j=y; j<h; j++) {                                           \
                    seg = data+(j*w);                                           \
                    if (seg[x] != cl2) {break;}                                 \
                    i = x;                                                      \
                    while ((seg[i] == cl2) && (i < w)) i += 1;                  \
                    i -= 1;                                                     \
                    if (j == y) vx = hx = i;                                    \
                    if (i < vx) vx = i;                                         \
                    if ((hyflag > 0) && (i >= hx)) {                            \
                        hy += 1;                                                \
                    } else {                                                    \
                        hyflag = 0;                                             \
                    }                                                           \
                }                                                               \
                vy = j-1;                                                       \
                                                                                \
                /* We now have two possible subrects: (x,y,hx,hy) and           \
                 * (x,y,vx,vy).  We'll choose the bigger of the two.            \
                 */                                                             \
                hw = hx-x+1;                                                    \
                hh = hy-y+1;                                                    \
                vw = vx-x+1;                                                    \
                vh = vy-y+1;                                                    \
                                                                                \
                thex = x;                                                       \
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -224,7 +224,7 @@
                     seg = data+(j*w);                                           \
                     if (seg[x] != cl2) {break;}                                 \
                     i = x;                                                      \
-                    while ((seg[i] == cl2) && (i < w)) i += 1;                  \
+                    while ((i < w) && (seg[i] == cl2)) i += 1;                  \
                     i -= 1;                                                     \
                     if (j == y) vx = hx = i;                                    \
                     if (i < vx) vx = i;                                         \
```
