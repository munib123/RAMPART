# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 5505_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5505_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 37-77 of the vulnerable file.

unsigned FAR *bits;
unsigned short FAR *work;
{
    unsigned len;               /* a code's length in bits */
    unsigned sym;               /* index of code symbols */
    unsigned min, max;          /* minimum and maximum code lengths */
    unsigned root;              /* number of index bits for root table */
    unsigned curr;              /* number of index bits for current table */
    unsigned drop;              /* code bits to drop for sub-table */
    int left;                   /* number of prefix codes available */
    unsigned used;              /* code entries in table used */
    unsigned huff;              /* Huffman code */
    unsigned incr;              /* for incrementing code, index */
    unsigned fill;              /* index for replicating entries */
    unsigned low;               /* low bits for current root entry */
    unsigned mask;              /* mask for low root bits */
    code here;                  /* table entry for duplication */
    code FAR *next;             /* next available space in table */
    const unsigned short FAR *base;     /* base value table to use */
    const unsigned short FAR *extra;    /* extra bits table to use */
    int end;                    /* use base and extra for symbol > end */
    unsigned short count[MAXBITS+1];    /* number of codes of each length */
    unsigned short offs[MAXBITS+1];     /* offsets in table for each length */
    static const unsigned short lbase[31] = { /* Length codes 257..285 base */
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
        35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0};
    static const unsigned short lext[31] = { /* Length codes 257..285 extra */
        16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18,
        19, 19, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 16, 203, 198};
    static const unsigned short dbase[32] = { /* Distance codes 0..29 base */
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
        257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
        8193, 12289, 16385, 24577, 0, 0};
    static const unsigned short dext[32] = { /* Distance codes 0..29 extra */
        16, 16, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22,
        23, 23, 24, 24, 25, 25, 26, 26, 27, 27,
        28, 28, 29, 29, 64, 64};

    /*
       Process a set of code lengths to create a canonical Huffman code.  The
       code lengths are lens[0..codes-1].  Each length corresponds to the
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -54,7 +54,7 @@
     code FAR *next;             /* next available space in table */
     const unsigned short FAR *base;     /* base value table to use */
     const unsigned short FAR *extra;    /* extra bits table to use */
-    int end;                    /* use base and extra for symbol > end */
+    unsigned match;             /* use base and extra for symbol >= match */
     unsigned short count[MAXBITS+1];    /* number of codes of each length */
     unsigned short offs[MAXBITS+1];     /* offsets in table for each length */
     static const unsigned short lbase[31] = { /* Length codes 257..285 base */
@@ -181,19 +181,17 @@
     switch (type) {
     case CODES:
         base = extra = work;    /* dummy value--not used */
-        end = 19;
+        match = 20;
         break;
     case LENS:
         base = lbase;
-        base -= 257;
         extra = lext;
-        extra -= 257;
-        end = 256;
+        match = 257;
         break;
     default:            /* DISTS */
         base = dbase;
         extra = dext;
-        end = -1;
+        match = 0;
     }
 
     /* initialize state for loop */
@@ -216,13 +214,13 @@
     for (;;) {
         /* create table entry */
         here.bits = (unsigned char)(len - drop);
-        if ((int)(work[sym]) < end) {
+        if (work[sym] + 1 < match) {
             here.op = (unsigned char)0;
             here.val = work[sym];
         }
-        else if ((int)(work[sym]) > end) {
-            here.op = (unsigned char)(extra[work[sym]]);
-            here.val = base[work[sym]];
+        else if (work[sym] >= match) {
+            here.op = (unsigned char)(extra[work[sym] - match]);
+            here.val = base[work[sym] - match];
         }
         else {
             here.op = (unsigned char)(32 + 64);         /* end of block */
```
