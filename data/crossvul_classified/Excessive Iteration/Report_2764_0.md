# CrossVul Fix Pair: Excessive Iteration in c
**Pair ID:** 2764_0
**Vulnerability Class:** Excessive Iteration
**CWE:** CWE-834
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2764_0`)

## Vulnerability Information & PoC

## Description
Excessive Iteration - If the iteration can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 732-773 of the vulnerable file.

            get_tag(s, name, value_type, value_len, 16);
        }
        av_freep(&name);
    }

    return 0;
}

static int asf_read_marker(AVFormatContext *s, int64_t size)
{
    AVIOContext *pb = s->pb;
    ASFContext *asf = s->priv_data;
    int i, count, name_len, ret;
    char name[1024];

    avio_rl64(pb);            // reserved 16 bytes
    avio_rl64(pb);            // ...
    count = avio_rl32(pb);    // markers count
    avio_rl16(pb);            // reserved 2 bytes
    name_len = avio_rl16(pb); // name length
    for (i = 0; i < name_len; i++)
        avio_r8(pb); // skip the name

    for (i = 0; i < count; i++) {
        int64_t pres_time;
        int name_len;

        avio_rl64(pb);             // offset, 8 bytes
        pres_time = avio_rl64(pb); // presentation time
        pres_time -= asf->hdr.preroll * 10000;
        avio_rl16(pb);             // entry length
        avio_rl32(pb);             // send time
        avio_rl32(pb);             // flags
        name_len = avio_rl32(pb);  // name length
        if ((ret = avio_get_str16le(pb, name_len * 2, name,
                                    sizeof(name))) < name_len)
            avio_skip(pb, name_len - ret);
        avpriv_new_chapter(s, i, (AVRational) { 1, 10000000 }, pres_time,
                           AV_NOPTS_VALUE, name);
    }

    return 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -749,12 +749,14 @@
     count = avio_rl32(pb);    // markers count
     avio_rl16(pb);            // reserved 2 bytes
     name_len = avio_rl16(pb); // name length
-    for (i = 0; i < name_len; i++)
-        avio_r8(pb); // skip the name
+    avio_skip(pb, name_len);
 
     for (i = 0; i < count; i++) {
         int64_t pres_time;
         int name_len;
+
+        if (avio_feof(pb))
+            return AVERROR_INVALIDDATA;
 
         avio_rl64(pb);             // offset, 8 bytes
         pres_time = avio_rl64(pb); // presentation time
```
