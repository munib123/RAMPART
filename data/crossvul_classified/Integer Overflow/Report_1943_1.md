# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 1943_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1943_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 79-119 of the vulnerable file.

 * If SDS_NOINIT is used, the buffer is left uninitialized;
 *
 * The string is always null-termined (all the sds strings are, always) so
 * even if you create an sds string with:
 *
 * mystring = sdsnewlen("abc",3);
 *
 * You can print the string with printf() as there is an implicit \0 at the
 * end of the string. However the string is binary safe and can contain
 * \0 characters in the middle, as the length is stored in the sds header. */
sds sdsnewlen(const void *init, size_t initlen) {
    void *sh;
    sds s;
    char type = sdsReqType(initlen);
    /* Empty strings are usually created in order to append. Use type 8
     * since type 5 is not good at this. */
    if (type == SDS_TYPE_5 && initlen == 0) type = SDS_TYPE_8;
    int hdrlen = sdsHdrSize(type);
    unsigned char *fp; /* flags pointer. */

    sh = s_malloc(hdrlen+initlen+1);
    if (sh == NULL) return NULL;
    if (init==SDS_NOINIT)
        init = NULL;
    else if (!init)
        memset(sh, 0, hdrlen+initlen+1);
    s = (char*)sh+hdrlen;
    fp = ((unsigned char*)s)-1;
    switch(type) {
        case SDS_TYPE_5: {
            *fp = type | (initlen << SDS_TYPE_BITS);
            break;
        }
        case SDS_TYPE_8: {
            SDS_HDR_VAR(8,s);
            sh->len = initlen;
            sh->alloc = initlen;
            *fp = type;
            break;
        }
        case SDS_TYPE_16: {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -96,6 +96,7 @@
     int hdrlen = sdsHdrSize(type);
     unsigned char *fp; /* flags pointer. */
 
+    assert(initlen + hdrlen + 1 > initlen); /* Catch size_t overflow */
     sh = s_malloc(hdrlen+initlen+1);
     if (sh == NULL) return NULL;
     if (init==SDS_NOINIT)
@@ -214,6 +215,7 @@
     len = sdslen(s);
     sh = (char*)s-sdsHdrSize(oldtype);
     newlen = (len+addlen);
+    assert(newlen > len);   /* Catch size_t overflow */
     if (newlen < SDS_MAX_PREALLOC)
         newlen *= 2;
     else
@@ -227,6 +229,7 @@
     if (type == SDS_TYPE_5) type = SDS_TYPE_8;
 
     hdrlen = sdsHdrSize(type);
+    assert(hdrlen + newlen + 1 > len);  /* Catch size_t overflow */
     if (oldtype==type) {
         newsh = s_realloc(sh, hdrlen+newlen+1);
         if (newsh == NULL) return NULL;
```
