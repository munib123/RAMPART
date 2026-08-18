# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3298_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3298_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 420-461 of the vulnerable file.

}

static int decode_zbuf(AVBPrint *bp, const uint8_t *data,
                       const uint8_t *data_end)
{
    z_stream zstream;
    unsigned char *buf;
    unsigned buf_size;
    int ret;

    zstream.zalloc = ff_png_zalloc;
    zstream.zfree  = ff_png_zfree;
    zstream.opaque = NULL;
    if (inflateInit(&zstream) != Z_OK)
        return AVERROR_EXTERNAL;
    zstream.next_in  = (unsigned char *)data;
    zstream.avail_in = data_end - data;
    av_bprint_init(bp, 0, -1);

    while (zstream.avail_in > 0) {
        av_bprint_get_buffer(bp, 1, &buf, &buf_size);
        if (!buf_size) {
            ret = AVERROR(ENOMEM);
            goto fail;
        }
        zstream.next_out  = buf;
        zstream.avail_out = buf_size;
        ret = inflate(&zstream, Z_PARTIAL_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            ret = AVERROR_EXTERNAL;
            goto fail;
        }
        bp->len += zstream.next_out - buf;
        if (ret == Z_STREAM_END)
            break;
    }
    inflateEnd(&zstream);
    bp->str[bp->len] = 0;
    return 0;

fail:
    inflateEnd(&zstream);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -437,13 +437,13 @@
     av_bprint_init(bp, 0, -1);
 
     while (zstream.avail_in > 0) {
-        av_bprint_get_buffer(bp, 1, &buf, &buf_size);
-        if (!buf_size) {
+        av_bprint_get_buffer(bp, 2, &buf, &buf_size);
+        if (buf_size < 2) {
             ret = AVERROR(ENOMEM);
             goto fail;
         }
         zstream.next_out  = buf;
-        zstream.avail_out = buf_size;
+        zstream.avail_out = buf_size - 1;
         ret = inflate(&zstream, Z_PARTIAL_FLUSH);
         if (ret != Z_OK && ret != Z_STREAM_END) {
             ret = AVERROR_EXTERNAL;
```
