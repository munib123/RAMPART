# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 3417_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3417_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1082-1122 of the vulnerable file.


        ret = avio_get_str16le(pb, desc_len, desc, sizeof(desc));
        avio_skip(pb, desc_len - ret);
        if (*desc)
            av_dict_set(&st->metadata, "title", desc, 0);

        avio_rl16(pb);   /* flags? */
        avio_rl32(pb);   /* data size */

        size = pb->buf_end - pb->buf_ptr;
        pd = (AVProbeData) { .buf      = av_mallocz(size + AVPROBE_PADDING_SIZE),
                             .buf_size = size };
        if (!pd.buf)
            goto error;
        memcpy(pd.buf, pb->buf_ptr, size);
        sub_demuxer = av_probe_input_format2(&pd, 1, &score);
        av_freep(&pd.buf);
        if (!sub_demuxer)
            goto error;

        if (!(ast->sub_ctx = avformat_alloc_context()))
            goto error;

        ast->sub_ctx->pb = pb;

        if (ff_copy_whiteblacklists(ast->sub_ctx, s) < 0)
            goto error;

        if (!avformat_open_input(&ast->sub_ctx, "", sub_demuxer, NULL)) {
            if (ast->sub_ctx->nb_streams != 1)
                goto error;
            ff_read_packet(ast->sub_ctx, &ast->sub_pkt);
            avcodec_parameters_copy(st->codecpar, ast->sub_ctx->streams[0]->codecpar);
            time_base = ast->sub_ctx->streams[0]->time_base;
            avpriv_set_pts_info(st, 64, time_base.num, time_base.den);
        }
        ast->sub_buffer = pkt->data;
        memset(pkt, 0, sizeof(*pkt));
        return 1;

error:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1099,6 +1099,9 @@
         if (!sub_demuxer)
             goto error;
 
+        if (strcmp(sub_demuxer->name, "srt") && strcmp(sub_demuxer->name, "ass"))
+            goto error;
+
         if (!(ast->sub_ctx = avformat_alloc_context()))
             goto error;
 
```
