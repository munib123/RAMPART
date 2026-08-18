# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 464_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `464_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 689-729 of the vulnerable file.

    avio_skip(pb, 4); // skip max_bitrate

    return 0;
}

static int parse_video_info(AVIOContext *pb, AVStream *st)
{
    uint16_t size_asf; // ASF-specific Format Data size
    uint32_t size_bmp; // BMP_HEADER-specific Format Data size
    unsigned int tag;

    st->codecpar->width  = avio_rl32(pb);
    st->codecpar->height = avio_rl32(pb);
    avio_skip(pb, 1); // skip reserved flags
    size_asf = avio_rl16(pb);
    tag = ff_get_bmp_header(pb, st, &size_bmp);
    st->codecpar->codec_tag = tag;
    st->codecpar->codec_id  = ff_codec_get_id(ff_codec_bmp_tags, tag);
    size_bmp = FFMAX(size_asf, size_bmp);

    if (size_bmp > BMP_HEADER_SIZE) {
        int ret;
        st->codecpar->extradata_size  = size_bmp - BMP_HEADER_SIZE;
        if (!(st->codecpar->extradata = av_malloc(st->codecpar->extradata_size +
                                               AV_INPUT_BUFFER_PADDING_SIZE))) {
            st->codecpar->extradata_size = 0;
            return AVERROR(ENOMEM);
        }
        memset(st->codecpar->extradata + st->codecpar->extradata_size , 0,
               AV_INPUT_BUFFER_PADDING_SIZE);
        if ((ret = avio_read(pb, st->codecpar->extradata,
                             st->codecpar->extradata_size)) < 0)
            return ret;
    }
    return 0;
}

static int asf_read_stream_properties(AVFormatContext *s, const GUIDParseTable *g)
{
    ASFContext *asf = s->priv_data;
    AVIOContext *pb = s->pb;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -706,7 +706,8 @@
     st->codecpar->codec_id  = ff_codec_get_id(ff_codec_bmp_tags, tag);
     size_bmp = FFMAX(size_asf, size_bmp);
 
-    if (size_bmp > BMP_HEADER_SIZE) {
+    if (size_bmp > BMP_HEADER_SIZE &&
+        size_bmp < INT_MAX - AV_INPUT_BUFFER_PADDING_SIZE) {
         int ret;
         st->codecpar->extradata_size  = size_bmp - BMP_HEADER_SIZE;
         if (!(st->codecpar->extradata = av_malloc(st->codecpar->extradata_size +
```
