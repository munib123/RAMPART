# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4836_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4836_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 217-257 of the vulnerable file.

                return AVERROR(EIO);
            written++;
            type = buf[0];
            if (hdr == RTMP_PS_TWELVEBYTES) {
                if (ffurl_read_complete(h, buf, 4) != 4)
                    return AVERROR(EIO);
                written += 4;
                extra = AV_RL32(buf);
            }
        }
    }
    if (ts_field == 0xFFFFFF) {
        if (ffurl_read_complete(h, buf, 4) != 4)
            return AVERROR(EIO);
        timestamp = AV_RB32(buf);
    } else {
        timestamp = ts_field;
    }
    if (hdr != RTMP_PS_TWELVEBYTES)
        timestamp += prev_pkt[channel_id].timestamp;

    if (!prev_pkt[channel_id].read) {
        if ((ret = ff_rtmp_packet_create(p, channel_id, type, timestamp,
                                         size)) < 0)
            return ret;
        p->read = written;
        p->offset = 0;
        prev_pkt[channel_id].ts_field   = ts_field;
        prev_pkt[channel_id].timestamp  = timestamp;
    } else {
        // previous packet in this channel hasn't completed reading
        RTMPPacket *prev = &prev_pkt[channel_id];
        p->data          = prev->data;
        p->size          = prev->size;
        p->channel_id    = prev->channel_id;
        p->type          = prev->type;
        p->ts_field      = prev->ts_field;
        p->extra         = prev->extra;
        p->offset        = prev->offset;
        p->read          = prev->read + written;
        p->timestamp     = prev->timestamp;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -234,6 +234,14 @@
     }
     if (hdr != RTMP_PS_TWELVEBYTES)
         timestamp += prev_pkt[channel_id].timestamp;
+
+    if (prev_pkt[channel_id].read && size != prev_pkt[channel_id].size) {
+        av_log(NULL, AV_LOG_ERROR, "RTMP packet size mismatch %d != %d\n",
+                size,
+                prev_pkt[channel_id].size);
+        ff_rtmp_packet_destroy(&prev_pkt[channel_id]);
+        prev_pkt[channel_id].read = 0;
+    }
 
     if (!prev_pkt[channel_id].read) {
         if ((ret = ff_rtmp_packet_create(p, channel_id, type, timestamp,
```
