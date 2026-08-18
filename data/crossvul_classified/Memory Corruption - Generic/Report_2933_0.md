# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2933_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2933_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 26-66 of the vulnerable file.


/*
 * Based on http://wiki.multimedia.cx/index.php?title=Smacker
 */

#include <stdio.h>
#include <stdlib.h>

#include "libavutil/channel_layout.h"

#define BITSTREAM_READER_LE
#include "avcodec.h"
#include "bitstream.h"
#include "bytestream.h"
#include "internal.h"
#include "mathops.h"
#include "vlc.h"

#define SMKTREE_BITS 9
#define SMK_NODE 0x80000000


typedef struct SmackVContext {
    AVCodecContext *avctx;
    AVFrame *pic;

    int *mmap_tbl, *mclr_tbl, *full_tbl, *type_tbl;
    int mmap_last[3], mclr_last[3], full_last[3], type_last[3];
} SmackVContext;

/**
 * Context used for code reconstructing
 */
typedef struct HuffContext {
    int length;
    int maxlength;
    int current;
    uint32_t *bits;
    int *lengths;
    int *values;
} HuffContext;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,7 +43,7 @@
 
 #define SMKTREE_BITS 9
 #define SMK_NODE 0x80000000
-
+#define SMKTREE_DECODE_MAX_RECURSION 32
 
 typedef struct SmackVContext {
     AVCodecContext *avctx;
@@ -97,6 +97,11 @@
 static int smacker_decode_tree(BitstreamContext *bc, HuffContext *hc,
                                uint32_t prefix, int length)
 {
+    if (length > SMKTREE_DECODE_MAX_RECURSION) {
+        av_log(NULL, AV_LOG_ERROR, "Maximum tree recursion level exceeded.\n");
+        return AVERROR_INVALIDDATA;
+    }
+
     if (!bitstream_read_bit(bc)) { // Leaf
         if(hc->current >= 256){
             av_log(NULL, AV_LOG_ERROR, "Tree size exceeded!\n");
```
