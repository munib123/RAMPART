# CrossVul Fix Pair: Improper Initialization in c
**Pair ID:** 881_0
**Vulnerability Class:** Improper Initialization
**CWE:** CWE-665
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `881_0`)

## Vulnerability Information & PoC

## Description
Improper Initialization - This can have security implications when the associated resource is expected to have certain properties or values, such as a variable that determines whether a user has been authenticated or not.

## Vulnerable Code
```c
Lines 68-108 of the vulnerable file.


    return result;
}

static int aa_read_header(AVFormatContext *s)
{
    int i, j, idx, largest_idx = -1;
    uint32_t nkey, nval, toc_size, npairs, header_seed = 0, start;
    char key[128], val[128], codec_name[64] = {0};
    uint8_t output[24], dst[8], src[8];
    int64_t largest_size = -1, current_size = -1, chapter_pos;
    struct toc_entry {
        uint32_t offset;
        uint32_t size;
    } TOC[MAX_TOC_ENTRIES];
    uint32_t header_key_part[4];
    uint8_t header_key[16] = {0};
    AADemuxContext *c = s->priv_data;
    AVIOContext *pb = s->pb;
    AVStream *st;

    /* parse .aa header */
    avio_skip(pb, 4); // file size
    avio_skip(pb, 4); // magic string
    toc_size = avio_rb32(pb); // TOC size
    avio_skip(pb, 4); // unidentified integer
    if (toc_size > MAX_TOC_ENTRIES)
        return AVERROR_INVALIDDATA;
    for (i = 0; i < toc_size; i++) { // read TOC
        avio_skip(pb, 4); // TOC entry index
        TOC[i].offset = avio_rb32(pb); // block offset
        TOC[i].size = avio_rb32(pb); // block size
    }
    avio_skip(pb, 24); // header termination block (ignored)
    npairs = avio_rb32(pb); // read dictionary entries
    if (npairs > MAX_DICTIONARY_ENTRIES)
        return AVERROR_INVALIDDATA;
    for (i = 0; i < npairs; i++) {
        memset(val, 0, sizeof(val));
        memset(key, 0, sizeof(key));
        avio_skip(pb, 1); // unidentified integer
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -85,6 +85,7 @@
     AADemuxContext *c = s->priv_data;
     AVIOContext *pb = s->pb;
     AVStream *st;
+    int ret;
 
     /* parse .aa header */
     avio_skip(pb, 4); // file size
@@ -118,8 +119,12 @@
             header_seed = atoi(val);
         } else if (!strcmp(key, "HeaderKey")) { // this looks like "1234567890 1234567890 1234567890 1234567890"
             av_log(s, AV_LOG_DEBUG, "HeaderKey is <%s>\n", val);
-            sscanf(val, "%"SCNu32"%"SCNu32"%"SCNu32"%"SCNu32,
+
+            ret = sscanf(val, "%"SCNu32"%"SCNu32"%"SCNu32"%"SCNu32,
                    &header_key_part[0], &header_key_part[1], &header_key_part[2], &header_key_part[3]);
+            if (ret != 4)
+                return AVERROR_INVALIDDATA;
+
             for (idx = 0; idx < 4; idx++) {
                 AV_WB32(&header_key[idx * 4], header_key_part[idx]); // convert each part to BE!
             }
```
