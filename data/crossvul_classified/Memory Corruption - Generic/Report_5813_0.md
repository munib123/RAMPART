# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5813_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5813_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 68-108 of the vulnerable file.

        return; \
    } \
}

static void rpza_decode_stream(RpzaContext *s)
{
    int width = s->avctx->width;
    int stride = s->frame.linesize[0] / 2;
    int row_inc = stride - 4;
    int stream_ptr = 0;
    int chunk_size;
    unsigned char opcode;
    int n_blocks;
    unsigned short colorA = 0, colorB;
    unsigned short color4[4];
    unsigned char index, idx;
    unsigned short ta, tb;
    unsigned short *pixels = (unsigned short *)s->frame.data[0];

    int row_ptr = 0;
    int pixel_ptr = 0;
    int block_ptr;
    int pixel_x, pixel_y;
    int total_blocks;

    /* First byte is always 0xe1. Warn if it's different */
    if (s->buf[stream_ptr] != 0xe1)
        av_log(s->avctx, AV_LOG_ERROR, "First chunk byte is 0x%02x instead of 0xe1\n",
            s->buf[stream_ptr]);

    /* Get chunk size, ingnoring first byte */
    chunk_size = AV_RB32(&s->buf[stream_ptr]) & 0x00FFFFFF;
    stream_ptr += 4;

    /* If length mismatch use size from MOV file and try to decode anyway */
    if (chunk_size != s->size)
        av_log(s->avctx, AV_LOG_ERROR, "MOV chunk size != encoded chunk size; using MOV chunk size\n");

    chunk_size = s->size;

    /* Number of 4x4 blocks in frame. */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -85,7 +85,7 @@
     unsigned short *pixels = (unsigned short *)s->frame.data[0];
 
     int row_ptr = 0;
-    int pixel_ptr = 0;
+    int pixel_ptr = -4;
     int block_ptr;
     int pixel_x, pixel_y;
     int total_blocks;
@@ -141,6 +141,7 @@
             colorA = AV_RB16 (&s->buf[stream_ptr]);
             stream_ptr += 2;
             while (n_blocks--) {
+                ADVANCE_BLOCK()
                 block_ptr = row_ptr + pixel_ptr;
                 for (pixel_y = 0; pixel_y < 4; pixel_y++) {
                     for (pixel_x = 0; pixel_x < 4; pixel_x++){
@@ -149,7 +150,6 @@
                     }
                     block_ptr += row_inc;
                 }
-                ADVANCE_BLOCK();
             }
             break;
 
@@ -188,6 +188,7 @@
             if (s->size - stream_ptr < n_blocks * 4)
                 return;
             while (n_blocks--) {
+                ADVANCE_BLOCK();
                 block_ptr = row_ptr + pixel_ptr;
                 for (pixel_y = 0; pixel_y < 4; pixel_y++) {
                     index = s->buf[stream_ptr++];
@@ -198,7 +199,6 @@
                     }
                     block_ptr += row_inc;
                 }
-                ADVANCE_BLOCK();
             }
             break;
 
@@ -206,6 +206,7 @@
         case 0x00:
             if (s->size - stream_ptr < 16)
                 return;
+            ADVANCE_BLOCK();
             block_ptr = row_ptr + pixel_ptr;
             for (pixel_y = 0; pixel_y < 4; pixel_y++) {
                 for (pixel_x = 0; pixel_x < 4; pixel_x++){
@@ -219,7 +220,6 @@
                 }
                 block_ptr += row_inc;
             }
-            ADVANCE_BLOCK();
             break;
 
         /* Unknown opcode */
```
