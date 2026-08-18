# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2656_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2656_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 375-415 of the vulnerable file.

    default:
        fprintf(stderr, "Error, unknown BMP header size %d\n", header->biSize);
        return OPJ_FALSE;
    }

    header->biWidth  = (OPJ_UINT32)getc(IN);
    header->biWidth |= (OPJ_UINT32)getc(IN) << 8;
    header->biWidth |= (OPJ_UINT32)getc(IN) << 16;
    header->biWidth |= (OPJ_UINT32)getc(IN) << 24;

    header->biHeight  = (OPJ_UINT32)getc(IN);
    header->biHeight |= (OPJ_UINT32)getc(IN) << 8;
    header->biHeight |= (OPJ_UINT32)getc(IN) << 16;
    header->biHeight |= (OPJ_UINT32)getc(IN) << 24;

    header->biPlanes  = (OPJ_UINT16)getc(IN);
    header->biPlanes |= (OPJ_UINT16)((OPJ_UINT32)getc(IN) << 8);

    header->biBitCount  = (OPJ_UINT16)getc(IN);
    header->biBitCount |= (OPJ_UINT16)((OPJ_UINT32)getc(IN) << 8);

    if (header->biSize >= 40U) {
        header->biCompression  = (OPJ_UINT32)getc(IN);
        header->biCompression |= (OPJ_UINT32)getc(IN) << 8;
        header->biCompression |= (OPJ_UINT32)getc(IN) << 16;
        header->biCompression |= (OPJ_UINT32)getc(IN) << 24;

        header->biSizeImage  = (OPJ_UINT32)getc(IN);
        header->biSizeImage |= (OPJ_UINT32)getc(IN) << 8;
        header->biSizeImage |= (OPJ_UINT32)getc(IN) << 16;
        header->biSizeImage |= (OPJ_UINT32)getc(IN) << 24;

        header->biXpelsPerMeter  = (OPJ_UINT32)getc(IN);
        header->biXpelsPerMeter |= (OPJ_UINT32)getc(IN) << 8;
        header->biXpelsPerMeter |= (OPJ_UINT32)getc(IN) << 16;
        header->biXpelsPerMeter |= (OPJ_UINT32)getc(IN) << 24;

        header->biYpelsPerMeter  = (OPJ_UINT32)getc(IN);
        header->biYpelsPerMeter |= (OPJ_UINT32)getc(IN) << 8;
        header->biYpelsPerMeter |= (OPJ_UINT32)getc(IN) << 16;
        header->biYpelsPerMeter |= (OPJ_UINT32)getc(IN) << 24;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -392,6 +392,10 @@
 
     header->biBitCount  = (OPJ_UINT16)getc(IN);
     header->biBitCount |= (OPJ_UINT16)((OPJ_UINT32)getc(IN) << 8);
+    if (header->biBitCount == 0) {
+        fprintf(stderr, "Error, invalid biBitCount %d\n", 0);
+        return OPJ_FALSE;
+    }
 
     if (header->biSize >= 40U) {
         header->biCompression  = (OPJ_UINT32)getc(IN);
```
