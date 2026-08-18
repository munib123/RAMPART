# CrossVul Fix Pair: Excessive Iteration in c
**Pair ID:** 2786_0
**Vulnerability Class:** Excessive Iteration
**CWE:** CWE-834
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2786_0`)

## Vulnerability Information & PoC

## Description
Excessive Iteration - If the iteration can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 6077-6117 of the vulnerable file.

    if (!tmp) {
        av_freep(&index);
        return AVERROR(ENOMEM);
    }
    mov->fragment_index_data = tmp;
    mov->fragment_index_data[mov->fragment_index_count++] = index;

    version = avio_r8(f);
    avio_rb24(f);
    index->track_id = avio_rb32(f);
    fieldlength = avio_rb32(f);
    index->item_count = avio_rb32(f);
    index->items = av_mallocz_array(
            index->item_count, sizeof(MOVFragmentIndexItem));
    if (!index->items) {
        index->item_count = 0;
        return AVERROR(ENOMEM);
    }
    for (i = 0; i < index->item_count; i++) {
        int64_t time, offset;
        if (version == 1) {
            time   = avio_rb64(f);
            offset = avio_rb64(f);
        } else {
            time   = avio_rb32(f);
            offset = avio_rb32(f);
        }
        index->items[i].time = time;
        index->items[i].moof_offset = offset;
        for (j = 0; j < ((fieldlength >> 4) & 3) + 1; j++)
            avio_r8(f);
        for (j = 0; j < ((fieldlength >> 2) & 3) + 1; j++)
            avio_r8(f);
        for (j = 0; j < ((fieldlength >> 0) & 3) + 1; j++)
            avio_r8(f);
    }

    avio_seek(f, pos + size, SEEK_SET);
    return 0;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6094,6 +6094,13 @@
     }
     for (i = 0; i < index->item_count; i++) {
         int64_t time, offset;
+
+        if (avio_feof(f)) {
+            index->item_count = 0;
+            av_freep(&index->items);
+            return AVERROR_INVALIDDATA;
+        }
+
         if (version == 1) {
             time   = avio_rb64(f);
             offset = avio_rb64(f);
```
