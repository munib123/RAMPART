# CrossVul Fix Pair: Excessive Iteration in c
**Pair ID:** 2761_0
**Vulnerability Class:** Excessive Iteration
**CWE:** CWE-834
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2761_0`)

## Vulnerability Information & PoC

## Description
Excessive Iteration - If the iteration can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 1206-1246 of the vulnerable file.


    if (tag != MKTAG('.','R','E','C'))
        return AVERROR_INVALIDDATA;

    if (avio_r8(pb) != 0)
        return AVERROR_INVALIDDATA;
    count = avio_rb32(pb);
    for (i = 0; i < count; i++) {
        if (avio_feof(pb))
            return AVERROR_INVALIDDATA;

        type = avio_r8(pb);
        tlen = avio_rb32(pb);
        avio_get_str(pb, tlen, key, sizeof(key));
        len = avio_rb32(pb);
        if (type == 5) {
            avio_get_str(pb, len, val, sizeof(val));
            av_log(s, AV_LOG_DEBUG, "%s = '%s'\n", key, val);
        } else if (type == 4) {
            av_log(s, AV_LOG_DEBUG, "%s = '0x", key);
            for (j = 0; j < len; j++)
                av_log(s, AV_LOG_DEBUG, "%X", avio_r8(pb));
            av_log(s, AV_LOG_DEBUG, "'\n");
        } else if (len == 4 && type == 3 && !strncmp(key, "StreamCount", tlen)) {
            nb_streams = value = avio_rb32(pb);
        } else if (len == 4 && type == 3) {
            value = avio_rb32(pb);
            av_log(s, AV_LOG_DEBUG, "%s = %d\n", key, value);
        } else {
            av_log(s, AV_LOG_DEBUG, "Skipping unsupported key: %s\n", key);
            avio_skip(pb, len);
        }
    }

    for (n = 0; n < nb_streams; n++) {
        st = avformat_new_stream(s, NULL);
        if (!st)
            return AVERROR(ENOMEM);
        st->priv_data = ff_rm_alloc_rmstream();
        if (!st->priv_data)
            return AVERROR(ENOMEM);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1223,8 +1223,11 @@
             av_log(s, AV_LOG_DEBUG, "%s = '%s'\n", key, val);
         } else if (type == 4) {
             av_log(s, AV_LOG_DEBUG, "%s = '0x", key);
-            for (j = 0; j < len; j++)
+            for (j = 0; j < len; j++) {
+                if (avio_feof(pb))
+                    return AVERROR_INVALIDDATA;
                 av_log(s, AV_LOG_DEBUG, "%X", avio_r8(pb));
+            }
             av_log(s, AV_LOG_DEBUG, "'\n");
         } else if (len == 4 && type == 3 && !strncmp(key, "StreamCount", tlen)) {
             nb_streams = value = avio_rb32(pb);
```
