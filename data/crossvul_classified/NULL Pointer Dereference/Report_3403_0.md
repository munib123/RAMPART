# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3403_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3403_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 70-110 of the vulnerable file.

                dctx->cur_byte = 0;
                dctx->remaining = 0;
                break;
            }
        }
    }

    if (pic_found && !dctx->remaining) {
        if (!buf_size) /* EOF considered as end of frame */
            return 0;
        for (; i < buf_size; i++) {
            dctx->cur_byte++;
            state = (state << 8) | buf[i];

            if (dctx->cur_byte == 24) {
                dctx->h = (state >> 32) & 0xFFFF;
            } else if (dctx->cur_byte == 26) {
                dctx->w = (state >> 32) & 0xFFFF;
            } else if (dctx->cur_byte == 42) {
                int cid = (state >> 32) & 0xFFFFFFFF;

                if (cid <= 0)
                    continue;

                dctx->remaining = avpriv_dnxhd_get_frame_size(cid);
                if (dctx->remaining <= 0) {
                    dctx->remaining = dnxhd_get_hr_frame_size(cid, dctx->w, dctx->h);
                    if (dctx->remaining <= 0)
                        return dctx->remaining;
                }
                if (buf_size - i >= dctx->remaining && (!dctx->interlaced || dctx->cur_field)) {
                    int remaining = dctx->remaining;

                    pc->frame_start_found = 0;
                    pc->state64 = -1;
                    dctx->interlaced = interlaced;
                    dctx->cur_field = 0;
                    dctx->cur_byte = 0;
                    dctx->remaining = 0;
                    return remaining;
                } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -87,16 +87,18 @@
                 dctx->w = (state >> 32) & 0xFFFF;
             } else if (dctx->cur_byte == 42) {
                 int cid = (state >> 32) & 0xFFFFFFFF;
+                int remaining;
 
                 if (cid <= 0)
                     continue;
 
-                dctx->remaining = avpriv_dnxhd_get_frame_size(cid);
-                if (dctx->remaining <= 0) {
-                    dctx->remaining = dnxhd_get_hr_frame_size(cid, dctx->w, dctx->h);
-                    if (dctx->remaining <= 0)
-                        return dctx->remaining;
+                remaining = avpriv_dnxhd_get_frame_size(cid);
+                if (remaining <= 0) {
+                    remaining = dnxhd_get_hr_frame_size(cid, dctx->w, dctx->h);
+                    if (remaining <= 0)
+                        continue;
                 }
+                dctx->remaining = remaining;
                 if (buf_size - i >= dctx->remaining && (!dctx->interlaced || dctx->cur_field)) {
                     int remaining = dctx->remaining;
 
```
