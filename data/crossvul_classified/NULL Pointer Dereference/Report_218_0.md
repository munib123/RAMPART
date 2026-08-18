# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 218_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `218_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 145-185 of the vulnerable file.

    if (hdr->lfe_on)
        hdr->channel_layout |= AV_CH_LOW_FREQUENCY;

    return 0;
}

// TODO: Better way to pass AC3HeaderInfo fields to mov muxer.
int avpriv_ac3_parse_header(AC3HeaderInfo **phdr, const uint8_t *buf,
                            size_t size)
{
    GetBitContext gb;
    AC3HeaderInfo *hdr;
    int err;

    if (!*phdr)
        *phdr = av_mallocz(sizeof(AC3HeaderInfo));
    if (!*phdr)
        return AVERROR(ENOMEM);
    hdr = *phdr;

    init_get_bits8(&gb, buf, size);
    err = ff_ac3_parse_header(&gb, hdr);
    if (err < 0)
        return AVERROR_INVALIDDATA;

    return get_bits_count(&gb);
}

int av_ac3_parse_header(const uint8_t *buf, size_t size,
                        uint8_t *bitstream_id, uint16_t *frame_size)
{
    GetBitContext gb;
    AC3HeaderInfo hdr;
    int err;

    init_get_bits8(&gb, buf, size);
    err = ff_ac3_parse_header(&gb, &hdr);
    if (err < 0)
        return AVERROR_INVALIDDATA;

    *bitstream_id = hdr.bitstream_id;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -162,7 +162,9 @@
         return AVERROR(ENOMEM);
     hdr = *phdr;
 
-    init_get_bits8(&gb, buf, size);
+    err = init_get_bits8(&gb, buf, size);
+    if (err < 0)
+        return AVERROR_INVALIDDATA;
     err = ff_ac3_parse_header(&gb, hdr);
     if (err < 0)
         return AVERROR_INVALIDDATA;
```
