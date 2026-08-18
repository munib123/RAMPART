# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1030_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1030_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 150-190 of the vulnerable file.

    {
        tmp = getdword((uint32_t*)&ld->start[1]);
        ld->bytes_left -= 4;
    } else {
        tmp = getdword_n((uint32_t*)&ld->start[1], ld->bytes_left);
        ld->bytes_left = 0;
    }
    ld->bufb = tmp;

    ld->bits_left = 32;
    ld->tail = &ld->start[2];
}

/* reset to a certain point */
void faad_resetbits(bitfile *ld, int bits)
{
    uint32_t tmp;
    int words = bits >> 5;
    int remainder = bits & 0x1F;

    ld->bytes_left = ld->buffer_size - words*4;

    if (ld->bytes_left >= 4)
    {
        tmp = getdword(&ld->start[words]);
        ld->bytes_left -= 4;
    } else {
        tmp = getdword_n(&ld->start[words], ld->bytes_left);
        ld->bytes_left = 0;
    }
    ld->bufa = tmp;

    if (ld->bytes_left >= 4)
    {
        tmp = getdword(&ld->start[words+1]);
        ld->bytes_left -= 4;
    } else {
        tmp = getdword_n(&ld->start[words+1], ld->bytes_left);
        ld->bytes_left = 0;
    }
    ld->bufb = tmp;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -167,7 +167,10 @@
     int words = bits >> 5;
     int remainder = bits & 0x1F;
 
-    ld->bytes_left = ld->buffer_size - words*4;
+    if (ld->buffer_size < words * 4)
+        ld->bytes_left = 0;
+    else
+        ld->bytes_left = ld->buffer_size - words*4;
 
     if (ld->bytes_left >= 4)
     {
```
