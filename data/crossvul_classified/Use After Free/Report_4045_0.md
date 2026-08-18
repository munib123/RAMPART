# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 4045_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4045_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 789-830 of the vulnerable file.

                if (!new_variant(c, &variant_info, line, url)) {
                    ret = AVERROR(ENOMEM);
                    goto fail;
                }
                is_variant = 0;
            }
            if (is_segment) {
                struct segment *seg;
                if (!pls) {
                    if (!new_variant(c, 0, url, NULL)) {
                        ret = AVERROR(ENOMEM);
                        goto fail;
                    }
                    pls = c->playlists[c->n_playlists - 1];
                }
                seg = av_malloc(sizeof(struct segment));
                if (!seg) {
                    ret = AVERROR(ENOMEM);
                    goto fail;
                }
                seg->duration = duration;
                seg->key_type = key_type;
                if (has_iv) {
                    memcpy(seg->iv, iv, sizeof(iv));
                } else {
                    int seq = pls->start_seq_no + pls->n_segments;
                    memset(seg->iv, 0, sizeof(seg->iv));
                    AV_WB32(seg->iv + 12, seq);
                }

                if (key_type != KEY_NONE) {
                    ff_make_absolute_url(tmp_str, sizeof(tmp_str), url, key);
                    seg->key = av_strdup(tmp_str);
                    if (!seg->key) {
                        av_free(seg);
                        ret = AVERROR(ENOMEM);
                        goto fail;
                    }
                } else {
                    seg->key = NULL;
                }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -806,8 +806,6 @@
                     ret = AVERROR(ENOMEM);
                     goto fail;
                 }
-                seg->duration = duration;
-                seg->key_type = key_type;
                 if (has_iv) {
                     memcpy(seg->iv, iv, sizeof(iv));
                 } else {
@@ -837,6 +835,11 @@
                     goto fail;
                 }
 
+                if (duration < 0.001 * AV_TIME_BASE) {
+                    duration = 0.001 * AV_TIME_BASE;
+                }
+                seg->duration = duration;
+                seg->key_type = key_type;
                 dynarray_add(&pls->segments, &pls->n_segments, seg);
                 is_segment = 0;
 
```
