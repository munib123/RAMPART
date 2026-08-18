# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5733_9
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5733_9`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 21-61 of the vulnerable file.

 * @file
 * filter for showing textual video frame information
 */

#include "libavutil/adler32.h"
#include "libavutil/imgutils.h"
#include "libavutil/internal.h"
#include "libavutil/pixdesc.h"
#include "libavutil/timestamp.h"
#include "avfilter.h"
#include "internal.h"
#include "video.h"

static int filter_frame(AVFilterLink *inlink, AVFrame *frame)
{
    AVFilterContext *ctx = inlink->dst;
    const AVPixFmtDescriptor *desc = av_pix_fmt_desc_get(inlink->format);
    uint32_t plane_checksum[4] = {0}, checksum = 0;
    int i, plane, vsub = desc->log2_chroma_h;

    for (plane = 0; plane < 4 && frame->data[plane]; plane++) {
        int64_t linesize = av_image_get_linesize(frame->format, frame->width, plane);
        uint8_t *data = frame->data[plane];
        int h = plane == 1 || plane == 2 ? FF_CEIL_RSHIFT(inlink->h, vsub) : inlink->h;

        if (linesize < 0)
            return linesize;

        for (i = 0; i < h; i++) {
            plane_checksum[plane] = av_adler32_update(plane_checksum[plane], data, linesize);
            checksum = av_adler32_update(checksum, data, linesize);
            data += frame->linesize[plane];
        }
    }

    av_log(ctx, AV_LOG_INFO,
           "n:%"PRId64" pts:%s pts_time:%s pos:%"PRId64" "
           "fmt:%s sar:%d/%d s:%dx%d i:%c iskey:%d type:%c "
           "checksum:%08X plane_checksum:[%08X",
           inlink->frame_count,
           av_ts2str(frame->pts), av_ts2timestr(frame->pts, &inlink->time_base), av_frame_get_pkt_pos(frame),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,7 +38,7 @@
     uint32_t plane_checksum[4] = {0}, checksum = 0;
     int i, plane, vsub = desc->log2_chroma_h;
 
-    for (plane = 0; plane < 4 && frame->data[plane]; plane++) {
+    for (plane = 0; plane < 4 && frame->data[plane] && frame->linesize[plane]; plane++) {
         int64_t linesize = av_image_get_linesize(frame->format, frame->width, plane);
         uint8_t *data = frame->data[plane];
         int h = plane == 1 || plane == 2 ? FF_CEIL_RSHIFT(inlink->h, vsub) : inlink->h;
@@ -68,7 +68,7 @@
            av_get_picture_type_char(frame->pict_type),
            checksum, plane_checksum[0]);
 
-    for (plane = 1; plane < 4 && frame->data[plane]; plane++)
+    for (plane = 1; plane < 4 && frame->data[plane] && frame->linesize[plane]; plane++)
         av_log(ctx, AV_LOG_INFO, " %08X", plane_checksum[plane]);
     av_log(ctx, AV_LOG_INFO, "]\n");
 
```
