# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 5396_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5396_2`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 389-429 of the vulnerable file.

#if defined(IMAGING_SMALL_MODEL)
#define THRESHOLD       16384L
#else
#define THRESHOLD       (2048*2048*4L)
#endif

Imaging
ImagingNew(const char* mode, int xsize, int ysize)
{
    int bytes;
    Imaging im;

    if (strlen(mode) == 1) {
        if (mode[0] == 'F' || mode[0] == 'I')
            bytes = 4;
        else
            bytes = 1;
    } else
        bytes = strlen(mode); /* close enough */

    if ((int64_t) xsize * (int64_t) ysize <= THRESHOLD / bytes) {
        im = ImagingNewBlock(mode, xsize, ysize);
        if (im)
            return im;
        /* assume memory error; try allocating in array mode instead */
        ImagingError_Clear();
    }

    return ImagingNewArray(mode, xsize, ysize);
}

Imaging
ImagingNew2(const char* mode, Imaging imOut, Imaging imIn)
{
    /* allocate or validate output image */

    if (imOut) {
        /* make sure images match */
        if (strcmp(imOut->mode, mode) != 0
            || imOut->xsize != imIn->xsize
            || imOut->ysize != imIn->ysize) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -406,6 +406,10 @@
     } else
         bytes = strlen(mode); /* close enough */
 
+    if (xsize < 0 || ysize < 0) {
+        return (Imaging) ImagingError_ValueError("bad image size");
+    }
+
     if ((int64_t) xsize * (int64_t) ysize <= THRESHOLD / bytes) {
         im = ImagingNewBlock(mode, xsize, ysize);
         if (im)
```
