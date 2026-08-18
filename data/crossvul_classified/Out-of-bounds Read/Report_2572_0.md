# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2572_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2572_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1395-1435 of the vulnerable file.

    while (count--) {
        left = *decoded1 - (*decoded0 / 2);
        right = left + *decoded0;

        *(decoded0++) = left;
        *(decoded1++) = right;
    }
}

static int ape_decode_frame(AVCodecContext *avctx, void *data,
                            int *got_frame_ptr, AVPacket *avpkt)
{
    AVFrame *frame     = data;
    const uint8_t *buf = avpkt->data;
    APEContext *s = avctx->priv_data;
    uint8_t *sample8;
    int16_t *sample16;
    int32_t *sample24;
    int i, ch, ret;
    int blockstodecode;

    /* this should never be negative, but bad things will happen if it is, so
       check it just to make sure. */
    av_assert0(s->samples >= 0);

    if(!s->samples){
        uint32_t nblocks, offset;
        int buf_size;

        if (!avpkt->size) {
            *got_frame_ptr = 0;
            return 0;
        }
        if (avpkt->size < 8) {
            av_log(avctx, AV_LOG_ERROR, "Packet is too small\n");
            return AVERROR_INVALIDDATA;
        }
        buf_size = avpkt->size & ~3;
        if (buf_size != avpkt->size) {
            av_log(avctx, AV_LOG_WARNING, "packet size is not a multiple of 4. "
                   "extra bytes at the end will be skipped.\n");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1412,6 +1412,7 @@
     int32_t *sample24;
     int i, ch, ret;
     int blockstodecode;
+    uint64_t decoded_buffer_size;
 
     /* this should never be negative, but bad things will happen if it is, so
        check it just to make sure. */
@@ -1467,7 +1468,7 @@
                 skip_bits_long(&s->gb, offset);
         }
 
-        if (!nblocks || nblocks > INT_MAX) {
+        if (!nblocks || nblocks > INT_MAX / 2 / sizeof(*s->decoded_buffer) - 8) {
             av_log(avctx, AV_LOG_ERROR, "Invalid sample count: %"PRIu32".\n",
                    nblocks);
             return AVERROR_INVALIDDATA;
@@ -1493,8 +1494,9 @@
         blockstodecode = s->samples;
 
     /* reallocate decoded sample buffer if needed */
-    av_fast_malloc(&s->decoded_buffer, &s->decoded_size,
-                   2 * FFALIGN(blockstodecode, 8) * sizeof(*s->decoded_buffer));
+    decoded_buffer_size = 2LL * FFALIGN(blockstodecode, 8) * sizeof(*s->decoded_buffer);
+    av_assert0(decoded_buffer_size <= INT_MAX);
+    av_fast_malloc(&s->decoded_buffer, &s->decoded_size, decoded_buffer_size);
     if (!s->decoded_buffer)
         return AVERROR(ENOMEM);
     memset(s->decoded_buffer, 0, s->decoded_size);
```
