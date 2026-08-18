# CrossVul Fix Pair: Excessive Iteration in c
**Pair ID:** 2766_0
**Vulnerability Class:** Excessive Iteration
**CWE:** CWE-834
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2766_0`)

## Vulnerability Information & PoC

## Description
Excessive Iteration - If the iteration can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 250-290 of the vulnerable file.

    if (!description)
        return AVERROR(ENOMEM);
    i = avio_get_str(pb, DESCRIPTION_SIZE, description, DESCRIPTION_SIZE + 1);
    if (i < DESCRIPTION_SIZE)
        avio_skip(pb, DESCRIPTION_SIZE - i);
    if (description[0])
        av_dict_set(&st->metadata, "description", description, AV_DICT_DONT_STRDUP_VAL);
    else
        av_free(description);

    avio_skip(pb, 1176); // RisingEdge ... cmUser

    set_metadata_int(&st->metadata, "enable_crop", avio_rl32(pb), 1);
    set_metadata_int(&st->metadata, "crop_left", avio_rl32(pb), 1);
    set_metadata_int(&st->metadata, "crop_top", avio_rl32(pb), 1);
    set_metadata_int(&st->metadata, "crop_right", avio_rl32(pb), 1);
    set_metadata_int(&st->metadata, "crop_bottom", avio_rl32(pb), 1);

    /* parse image offsets */
    avio_seek(pb, offImageOffsets, SEEK_SET);
    for (i = 0; i < st->duration; i++)
        av_add_index_entry(st, avio_rl64(pb), i, 0, 0, AVINDEX_KEYFRAME);

    return 0;
}

static int cine_read_packet(AVFormatContext *avctx, AVPacket *pkt)
{
    CineDemuxContext *cine = avctx->priv_data;
    AVStream *st = avctx->streams[0];
    AVIOContext *pb = avctx->pb;
    int n, size, ret;

    if (cine->pts >= st->duration)
        return AVERROR_EOF;

    avio_seek(pb, st->index_entries[cine->pts].pos, SEEK_SET);
    n = avio_rl32(pb);
    if (n < 8)
        return AVERROR_INVALIDDATA;
    avio_skip(pb, n - 8);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -267,8 +267,12 @@
 
     /* parse image offsets */
     avio_seek(pb, offImageOffsets, SEEK_SET);
-    for (i = 0; i < st->duration; i++)
+    for (i = 0; i < st->duration; i++) {
+        if (avio_feof(pb))
+            return AVERROR_INVALIDDATA;
+
         av_add_index_entry(st, avio_rl64(pb), i, 0, 0, AVINDEX_KEYFRAME);
+    }
 
     return 0;
 }
```
