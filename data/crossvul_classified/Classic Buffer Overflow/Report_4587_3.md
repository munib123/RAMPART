# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 4587_3
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4587_3`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 8-48 of the vulnerable file.

 * 2017-07-28 mb    fixed for images larger than 64KB
 * 2017-07-20 mb	created
 *
 * Copyright (c) Mickael Bonfill 2017.
 *
 * See the README file for information on usage and redistribution.
 */

#include "Imaging.h"
#include "Sgi.h"

#define SGI_HEADER_SIZE 512
#define RLE_COPY_FLAG 0x80
#define RLE_MAX_RUN 0x7f

static void read4B(UINT32* dest, UINT8* buf)
{
    *dest = (UINT32)((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]);
}

static int expandrow(UINT8* dest, UINT8* src, int n, int z)
{
    UINT8 pixel, count;

    for (;n > 0; n--)
    {
        pixel = *src++;
        if (n == 1 && pixel != 0)
            return n;
        count = pixel & RLE_MAX_RUN;
        if (!count)
            return count;
        if (pixel & RLE_COPY_FLAG) {
            while(count--) {
                *dest = *src++;
                dest += z;
            }

        }
        else {
            pixel = *src++;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,7 @@
     *dest = (UINT32)((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]);
 }
 
-static int expandrow(UINT8* dest, UINT8* src, int n, int z)
+static int expandrow(UINT8* dest, UINT8* src, int n, int z, int xsize)
 {
     UINT8 pixel, count;
 
@@ -37,6 +37,9 @@
         count = pixel & RLE_MAX_RUN;
         if (!count)
             return count;
+        if (count > xsize) {
+            return -1;
+        }
         if (pixel & RLE_COPY_FLAG) {
             while(count--) {
                 *dest = *src++;
@@ -56,7 +59,7 @@
     return 0;
 }
 
-static int expandrow2(UINT8* dest, const UINT8* src, int n, int z)
+static int expandrow2(UINT8* dest, const UINT8* src, int n, int z, int xsize)
 {
     UINT8 pixel, count;
 
@@ -70,6 +73,9 @@
         count = pixel & RLE_MAX_RUN;
         if (!count)
             return count;
+        if (count > xsize) {
+            return -1;
+        }
         if (pixel & RLE_COPY_FLAG) {
             while(count--) {
                 memcpy(dest, src, 2);
@@ -96,6 +102,7 @@
     UINT8 *ptr;
     SGISTATE *c;
     int err = 0;
+    int status;
 
     /* Get all data from File descriptor */
     c = (SGISTATE*)state->context;
@@ -164,12 +171,16 @@
 
             /* row decompression */
             if (c->bpc ==1) {
-                if(expandrow(&state->buffer[c->channo], &ptr[c->rleoffset], c->rlelength, im->bands))
-                    goto sgi_finish_decode;
+                status = expandrow(&state->buffer[c->channo], &ptr[c->rleoffset], c->rlelength, im->bands, im->xsize);
             }
             else {
-                if(expandrow2(&state->buffer[c->channo * 2], &ptr[c->rleoffset], c->rlelength, im->bands))
-                    goto sgi_finish_decode;
+                status = expandrow2(&state->buffer[c->channo * 2], &ptr[c->rleoffset], c->rlelength, im->bands, im->xsize);
+            }
+            if (status == -1) {
+                state->errcode = IMAGING_CODEC_OVERRUN;
+                return -1;
+            } else if (status == 1) {
+                goto sgi_finish_decode;
             }
 
             state->count += c->rlelength;
```
