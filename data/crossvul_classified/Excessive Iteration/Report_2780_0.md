# CrossVul Fix Pair: Excessive Iteration in c
**Pair ID:** 2780_0
**Vulnerability Class:** Excessive Iteration
**CWE:** CWE-834
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2780_0`)

## Vulnerability Information & PoC

## Description
Excessive Iteration - If the iteration can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 318-358 of the vulnerable file.

            *p++ = '\0';
            av_log(s, AV_LOG_TRACE, "NSV NSVf INFO: %s='%s'\n", token, value);
            av_dict_set(&s->metadata, token, value, 0);
        }
        av_free(strings);
    }
    if (avio_feof(pb))
        return -1;

    av_log(s, AV_LOG_TRACE, "NSV got infos; filepos %"PRId64"\n", avio_tell(pb));

    if (table_entries_used > 0) {
        int i;
        nsv->index_entries = table_entries_used;
        if((unsigned)table_entries_used >= UINT_MAX / sizeof(uint32_t))
            return -1;
        nsv->nsvs_file_offset = av_malloc_array((unsigned)table_entries_used, sizeof(uint32_t));
        if (!nsv->nsvs_file_offset)
            return AVERROR(ENOMEM);

        for(i=0;i<table_entries_used;i++)
            nsv->nsvs_file_offset[i] = avio_rl32(pb) + size;

        if(table_entries > table_entries_used &&
           avio_rl32(pb) == MKTAG('T','O','C','2')) {
            nsv->nsvs_timestamps = av_malloc_array((unsigned)table_entries_used, sizeof(uint32_t));
            if (!nsv->nsvs_timestamps)
                return AVERROR(ENOMEM);
            for(i=0;i<table_entries_used;i++) {
                nsv->nsvs_timestamps[i] = avio_rl32(pb);
            }
        }
    }

    av_log(s, AV_LOG_TRACE, "NSV got index; filepos %"PRId64"\n", avio_tell(pb));

    avio_seek(pb, nsv->base_offset + size, SEEK_SET); /* required for dumbdriving-271.nsv (2 extra bytes) */

    if (avio_feof(pb))
        return -1;
    nsv->state = NSV_HAS_READ_NSVF;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -335,8 +335,11 @@
         if (!nsv->nsvs_file_offset)
             return AVERROR(ENOMEM);
 
-        for(i=0;i<table_entries_used;i++)
+        for(i=0;i<table_entries_used;i++) {
+            if (avio_feof(pb))
+                return AVERROR_INVALIDDATA;
             nsv->nsvs_file_offset[i] = avio_rl32(pb) + size;
+        }
 
         if(table_entries > table_entries_used &&
            avio_rl32(pb) == MKTAG('T','O','C','2')) {
```
