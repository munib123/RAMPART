# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3984_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3984_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 15-55 of the vulnerable file.


/*
    jbig2dec
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "os_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>             /* memcpy() */

#include "jbig2.h"
#include "jbig2_priv.h"
#include "jbig2_image.h"

#if !defined (INT32_MAX)
#define INT32_MAX  0x7fffffff
#endif

/* allocate a Jbig2Image structure and its associated bitmap */
Jbig2Image *
jbig2_image_new(Jbig2Ctx *ctx, uint32_t width, uint32_t height)
{
    Jbig2Image *image;
    uint32_t stride;

    if (width == 0 || height == 0) {
        jbig2_error(ctx, JBIG2_SEVERITY_FATAL, -1, "failed to create zero sized image");
        return NULL;
    }

    image = jbig2_new(ctx, Jbig2Image, 1);
    if (image == NULL) {
        jbig2_error(ctx, JBIG2_SEVERITY_FATAL, -1, "failed to allocate image");
        return NULL;
    }

    stride = ((width - 1) >> 3) + 1;    /* generate a byte-aligned stride */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,6 +32,9 @@
 
 #if !defined (INT32_MAX)
 #define INT32_MAX  0x7fffffff
+#endif
+#if !defined (UINT32_MAX)
+#define UINT32_MAX  0xffffffffu
 #endif
 
 /* allocate a Jbig2Image structure and its associated bitmap */
@@ -351,6 +354,15 @@
     if (src == NULL)
         return 0;
 
+    if ((UINT32_MAX - src->width  < (x > 0 ? x : -x)) ||
+        (UINT32_MAX - src->height < (y > 0 ? y : -y)))
+    {
+#ifdef JBIG2_DEBUG
+        jbig2_error(ctx, JBIG2_SEVERITY_DEBUG, -1, "overflow in compose_image");
+#endif
+        return 0;
+    }
+
     /* This code takes a src image and combines it onto dst at offset (x,y), with operation op. */
 
     /* Data is packed msb first within a byte, so with bits numbered: 01234567.
```
