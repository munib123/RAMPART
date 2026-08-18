# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 463_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `463_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 77-134 of the vulnerable file.

            chunksize = AV_RL64(p + sizeof(ff_asf_guid));
        }
        if (!chunksize || chunksize > end - p) {
            av_log(NULL, AV_LOG_ERROR,
                   "Corrupt stream (header chunksize %"PRId64" is invalid)\n",
                   chunksize);
            return AVERROR_INVALIDDATA;
        }
        if (!memcmp(p, ff_asf_file_header, sizeof(ff_asf_guid))) {
            /* read packet size */
            if (end - p > sizeof(ff_asf_guid) * 2 + 68) {
                mms->asf_packet_len = AV_RL32(p + sizeof(ff_asf_guid) * 2 + 64);
                if (mms->asf_packet_len <= 0 || mms->asf_packet_len > sizeof(mms->in_buffer)) {
                    av_log(NULL, AV_LOG_ERROR,
                           "Corrupt stream (too large pkt_len %d)\n",
                           mms->asf_packet_len);
                    return AVERROR_INVALIDDATA;
                }
            }
        } else if (!memcmp(p, ff_asf_stream_header, sizeof(ff_asf_guid))) {
            flags     = AV_RL16(p + sizeof(ff_asf_guid)*3 + 24);
            stream_id = flags & 0x7F;
            //The second condition is for checking CS_PKT_STREAM_ID_REQUEST packet size,
            //we can calculate the packet size by stream_num.
            //Please see function send_stream_selection_request().
            if (mms->stream_num < MMS_MAX_STREAMS &&
                    46 + mms->stream_num * 6 < sizeof(mms->out_buffer)) {
                mms->streams = av_fast_realloc(mms->streams,
                                   &mms->nb_streams_allocated,
                                   (mms->stream_num + 1) * sizeof(MMSStream));
                if (!mms->streams)
                    return AVERROR(ENOMEM);
                mms->streams[mms->stream_num].id = stream_id;
                mms->stream_num++;
            } else {
                av_log(NULL, AV_LOG_ERROR,
                       "Corrupt stream (too many A/V streams)\n");
                return AVERROR_INVALIDDATA;
            }
        } else if (!memcmp(p, ff_asf_ext_stream_header, sizeof(ff_asf_guid))) {
            if (end - p >= 88) {
                int stream_count = AV_RL16(p + 84), ext_len_count = AV_RL16(p + 86);
                uint64_t skip_bytes = 88;
                while (stream_count--) {
                    if (end - p < skip_bytes + 4) {
                        av_log(NULL, AV_LOG_ERROR,
                               "Corrupt stream (next stream name length is not in the buffer)\n");
                        return AVERROR_INVALIDDATA;
                    }
                    skip_bytes += 4 + AV_RL16(p + skip_bytes + 2);
                }
                while (ext_len_count--) {
                    if (end - p < skip_bytes + 22) {
                        av_log(NULL, AV_LOG_ERROR,
                               "Corrupt stream (next extension system info length is not in the buffer)\n");
                        return AVERROR_INVALIDDATA;
                    }
                    skip_bytes += 22 + AV_RL32(p + skip_bytes + 18);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -94,24 +94,26 @@
                 }
             }
         } else if (!memcmp(p, ff_asf_stream_header, sizeof(ff_asf_guid))) {
-            flags     = AV_RL16(p + sizeof(ff_asf_guid)*3 + 24);
-            stream_id = flags & 0x7F;
-            //The second condition is for checking CS_PKT_STREAM_ID_REQUEST packet size,
-            //we can calculate the packet size by stream_num.
-            //Please see function send_stream_selection_request().
-            if (mms->stream_num < MMS_MAX_STREAMS &&
-                    46 + mms->stream_num * 6 < sizeof(mms->out_buffer)) {
-                mms->streams = av_fast_realloc(mms->streams,
-                                   &mms->nb_streams_allocated,
-                                   (mms->stream_num + 1) * sizeof(MMSStream));
-                if (!mms->streams)
-                    return AVERROR(ENOMEM);
-                mms->streams[mms->stream_num].id = stream_id;
-                mms->stream_num++;
-            } else {
-                av_log(NULL, AV_LOG_ERROR,
-                       "Corrupt stream (too many A/V streams)\n");
-                return AVERROR_INVALIDDATA;
+            if (end - p >= (sizeof(ff_asf_guid) * 3 + 26)) {
+                flags     = AV_RL16(p + sizeof(ff_asf_guid)*3 + 24);
+                stream_id = flags & 0x7F;
+                //The second condition is for checking CS_PKT_STREAM_ID_REQUEST packet size,
+                //we can calculate the packet size by stream_num.
+                //Please see function send_stream_selection_request().
+                if (mms->stream_num < MMS_MAX_STREAMS &&
+                        46 + mms->stream_num * 6 < sizeof(mms->out_buffer)) {
+                    mms->streams = av_fast_realloc(mms->streams,
+                                       &mms->nb_streams_allocated,
+                                       (mms->stream_num + 1) * sizeof(MMSStream));
+                    if (!mms->streams)
+                        return AVERROR(ENOMEM);
+                    mms->streams[mms->stream_num].id = stream_id;
+                    mms->stream_num++;
+                } else {
+                    av_log(NULL, AV_LOG_ERROR,
+                           "Corrupt stream (too many A/V streams)\n");
+                    return AVERROR_INVALIDDATA;
+                }
             }
         } else if (!memcmp(p, ff_asf_ext_stream_header, sizeof(ff_asf_guid))) {
             if (end - p >= 88) {
@@ -143,6 +145,12 @@
             }
         } else if (!memcmp(p, ff_asf_head1_guid, sizeof(ff_asf_guid))) {
             chunksize = 46; // see references [2] section 3.4. This should be set 46.
+            if (chunksize > end - p) {
+                av_log(NULL, AV_LOG_ERROR,
+                    "Corrupt stream (header chunksize %"PRId64" is invalid)\n",
+                    chunksize);
+                return AVERROR_INVALIDDATA;
+            }
         }
         p += chunksize;
     }
```
