# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3378_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3378_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 3218-3264 of the vulnerable file.

                 && ! ONIGENC_IS_MBC_CRNL(reg->enc, p, end)
#endif
                 )
          goto retry_gate;
        break;
      }
    }

    if (reg->dmax == 0) {
      *low = p;
      if (low_prev) {
        if (*low > s)
          *low_prev = onigenc_get_prev_char_head(reg->enc, s, p);
        else
          *low_prev = onigenc_get_prev_char_head(reg->enc,
                                                 (pprev ? pprev : str), p);
      }
    }
    else {
      if (reg->dmax != ONIG_INFINITE_DISTANCE) {
        *low = p - reg->dmax;
        if (*low > s) {
          *low = onigenc_get_right_adjust_char_head_with_prev(reg->enc, s,
                                          *low, (const UChar** )low_prev);
          if (low_prev && IS_NULL(*low_prev))
            *low_prev = onigenc_get_prev_char_head(reg->enc,
                                                   (pprev ? pprev : s), *low);
        }
        else {
          if (low_prev)
            *low_prev = onigenc_get_prev_char_head(reg->enc,
                                                   (pprev ? pprev : str), *low);
        }
      }
    }
    /* no needs to adjust *high, *high is used as range check only */
    *high = p - reg->dmin;

#ifdef ONIG_DEBUG_SEARCH
    fprintf(stderr,
    "forward_search_range success: low: %d, high: %d, dmin: %d, dmax: %d\n",
	    (int )(*low - str), (int )(*high - str), reg->dmin, reg->dmax);
#endif
    return 1; /* success */
  }

  return 0; /* fail */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3235,18 +3235,25 @@
     }
     else {
       if (reg->dmax != ONIG_INFINITE_DISTANCE) {
-        *low = p - reg->dmax;
-        if (*low > s) {
-          *low = onigenc_get_right_adjust_char_head_with_prev(reg->enc, s,
-                                          *low, (const UChar** )low_prev);
-          if (low_prev && IS_NULL(*low_prev))
-            *low_prev = onigenc_get_prev_char_head(reg->enc,
-                                                   (pprev ? pprev : s), *low);
+        if (p - str < reg->dmax) {
+          *low = (UChar* )str;
+          if (low_prev)
+            *low_prev = onigenc_get_prev_char_head(reg->enc, str, *low);
         }
         else {
-          if (low_prev)
-            *low_prev = onigenc_get_prev_char_head(reg->enc,
-                                                   (pprev ? pprev : str), *low);
+          *low = p - reg->dmax;
+          if (*low > s) {
+            *low = onigenc_get_right_adjust_char_head_with_prev(reg->enc, s,
+                                                 *low, (const UChar** )low_prev);
+            if (low_prev && IS_NULL(*low_prev))
+              *low_prev = onigenc_get_prev_char_head(reg->enc,
+                                                     (pprev ? pprev : s), *low);
+          }
+          else {
+            if (low_prev)
+              *low_prev = onigenc_get_prev_char_head(reg->enc,
+                                                     (pprev ? pprev : str), *low);
+          }
         }
       }
     }
```
