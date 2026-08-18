# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 828_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `828_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 4615-4655 of the vulnerable file.


    if (strcmp(tokens[1].value, "tune") == 0 && ntokens >= 7) {
        if (!safe_strtoul(tokens[2].value, &pct_hot) ||
            !safe_strtoul(tokens[3].value, &pct_warm) ||
            !safe_strtod(tokens[4].value, &hot_factor) ||
            !safe_strtod(tokens[5].value, &factor)) {
            out_string(c, "ERROR");
        } else {
            if (pct_hot + pct_warm > 80) {
                out_string(c, "ERROR hot and warm pcts must not exceed 80");
            } else if (factor <= 0 || hot_factor <= 0) {
                out_string(c, "ERROR hot/warm age factors must be greater than 0");
            } else {
                settings.hot_lru_pct = pct_hot;
                settings.warm_lru_pct = pct_warm;
                settings.hot_max_factor = hot_factor;
                settings.warm_max_factor = factor;
                out_string(c, "OK");
            }
        }
    } else if (strcmp(tokens[1].value, "mode") == 0 && ntokens >= 3 &&
               settings.lru_maintainer_thread) {
        if (strcmp(tokens[2].value, "flat") == 0) {
            settings.lru_segmented = false;
            out_string(c, "OK");
        } else if (strcmp(tokens[2].value, "segmented") == 0) {
            settings.lru_segmented = true;
            out_string(c, "OK");
        } else {
            out_string(c, "ERROR");
        }
    } else if (strcmp(tokens[1].value, "temp_ttl") == 0 && ntokens >= 3 &&
               settings.lru_maintainer_thread) {
        if (!safe_strtol(tokens[2].value, &ttl)) {
            out_string(c, "ERROR");
        } else {
            if (ttl < 0) {
                settings.temp_lru = false;
            } else {
                settings.temp_lru = true;
                settings.temporary_ttl = ttl;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4632,7 +4632,7 @@
                 out_string(c, "OK");
             }
         }
-    } else if (strcmp(tokens[1].value, "mode") == 0 && ntokens >= 3 &&
+    } else if (strcmp(tokens[1].value, "mode") == 0 && ntokens >= 4 &&
                settings.lru_maintainer_thread) {
         if (strcmp(tokens[2].value, "flat") == 0) {
             settings.lru_segmented = false;
@@ -4643,7 +4643,7 @@
         } else {
             out_string(c, "ERROR");
         }
-    } else if (strcmp(tokens[1].value, "temp_ttl") == 0 && ntokens >= 3 &&
+    } else if (strcmp(tokens[1].value, "temp_ttl") == 0 && ntokens >= 4 &&
                settings.lru_maintainer_thread) {
         if (!safe_strtol(tokens[2].value, &ttl)) {
             out_string(c, "ERROR");
```
