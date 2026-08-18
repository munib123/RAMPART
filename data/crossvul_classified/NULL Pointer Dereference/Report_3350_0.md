# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3350_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3350_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 503-543 of the vulnerable file.

        return -1;
    /* now read the first chunk, so we can attempt to decode more info */
    err = nsv_read_chunk(s, 1);

    av_log(s, AV_LOG_TRACE, "parsed header\n");
    return err;
}

static int nsv_read_chunk(AVFormatContext *s, int fill_header)
{
    NSVContext *nsv = s->priv_data;
    AVIOContext *pb = s->pb;
    AVStream *st[2] = {NULL, NULL};
    NSVStream *nst;
    AVPacket *pkt;
    int i, err = 0;
    uint8_t auxcount; /* number of aux metadata, also 4 bits of vsize */
    uint32_t vsize;
    uint16_t asize;
    uint16_t auxsize;

    if (nsv->ahead[0].data || nsv->ahead[1].data)
        return 0; //-1; /* hey! eat what you've in your plate first! */

null_chunk_retry:
    if (pb->eof_reached)
        return -1;

    for (i = 0; i < NSV_MAX_RESYNC_TRIES && nsv->state < NSV_FOUND_NSVS && !err; i++)
        err = nsv_resync(s);
    if (err < 0)
        return err;
    if (nsv->state == NSV_FOUND_NSVS)
        err = nsv_parse_NSVs_header(s);
    if (err < 0)
        return err;
    if (nsv->state != NSV_HAS_READ_NSVS && nsv->state != NSV_FOUND_BEEF)
        return -1;

    auxcount = avio_r8(pb);
    vsize = avio_rl16(pb);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -520,6 +520,7 @@
     uint32_t vsize;
     uint16_t asize;
     uint16_t auxsize;
+    int ret;
 
     if (nsv->ahead[0].data || nsv->ahead[1].data)
         return 0; //-1; /* hey! eat what you've in your plate first! */
@@ -571,7 +572,8 @@
     if (vsize && st[NSV_ST_VIDEO]) {
         nst = st[NSV_ST_VIDEO]->priv_data;
         pkt = &nsv->ahead[NSV_ST_VIDEO];
-        av_get_packet(pb, pkt, vsize);
+        if ((ret = av_get_packet(pb, pkt, vsize)) < 0)
+            return ret;
         pkt->stream_index = st[NSV_ST_VIDEO]->index;//NSV_ST_VIDEO;
         pkt->dts = nst->frame_offset;
         pkt->flags |= nsv->state == NSV_HAS_READ_NSVS ? AV_PKT_FLAG_KEY : 0; /* keyframe only likely on a sync frame */
@@ -615,7 +617,8 @@
                        bps, channels, samplerate);
             }
         }
-        av_get_packet(pb, pkt, asize);
+        if ((ret = av_get_packet(pb, pkt, asize)) < 0)
+            return ret;
         pkt->stream_index = st[NSV_ST_AUDIO]->index;//NSV_ST_AUDIO;
         pkt->flags |= nsv->state == NSV_HAS_READ_NSVS ? AV_PKT_FLAG_KEY : 0; /* keyframe only likely on a sync frame */
         if( nsv->state == NSV_HAS_READ_NSVS && st[NSV_ST_VIDEO] ) {
```
