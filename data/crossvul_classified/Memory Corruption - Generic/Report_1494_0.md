# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1494_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1494_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1791-1831 of the vulnerable file.

            xi = xs;
            xs = sk_X509_value(ctx->chain, n);
        }
    }
    ok = 1;
 end:
    return ok;
}

int X509_cmp_current_time(const ASN1_TIME *ctm)
{
    return X509_cmp_time(ctm, NULL);
}

int X509_cmp_time(const ASN1_TIME *ctm, time_t *cmp_time)
{
    char *str;
    ASN1_TIME atm;
    long offset;
    char buff1[24], buff2[24], *p;
    int i, j;

    p = buff1;
    i = ctm->length;
    str = (char *)ctm->data;
    if (ctm->type == V_ASN1_UTCTIME) {
        if ((i < 11) || (i > 17))
            return 0;
        memcpy(p, str, 10);
        p += 10;
        str += 10;
    } else {
        if (i < 13)
            return 0;
        memcpy(p, str, 12);
        p += 12;
        str += 12;
    }

    if ((*str == 'Z') || (*str == '-') || (*str == '+')) {
        *(p++) = '0';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1808,46 +1808,83 @@
     ASN1_TIME atm;
     long offset;
     char buff1[24], buff2[24], *p;
-    int i, j;
+    int i, j, remaining;
 
     p = buff1;
-    i = ctm->length;
+    remaining = ctm->length;
     str = (char *)ctm->data;
+    /*
+     * Note that the following (historical) code allows much more slack in the
+     * time format than RFC5280. In RFC5280, the representation is fixed:
+     * UTCTime: YYMMDDHHMMSSZ
+     * GeneralizedTime: YYYYMMDDHHMMSSZ
+     */
     if (ctm->type == V_ASN1_UTCTIME) {
-        if ((i < 11) || (i > 17))
+        /* YYMMDDHHMM[SS]Z or YYMMDDHHMM[SS](+-)hhmm */
+        int min_length = sizeof("YYMMDDHHMMZ") - 1;
+        int max_length = sizeof("YYMMDDHHMMSS+hhmm") - 1;
+        if (remaining < min_length || remaining > max_length)
             return 0;
         memcpy(p, str, 10);
         p += 10;
         str += 10;
+        remaining -= 10;
     } else {
-        if (i < 13)
+        /* YYYYMMDDHHMM[SS[.fff]]Z or YYYYMMDDHHMM[SS[.f[f[f]]]](+-)hhmm */
+        int min_length = sizeof("YYYYMMDDHHMMZ") - 1;
+        int max_length = sizeof("YYYYMMDDHHMMSS.fff+hhmm") - 1;
+        if (remaining < min_length || remaining > max_length)
             return 0;
         memcpy(p, str, 12);
         p += 12;
         str += 12;
+        remaining -= 12;
     }
 
     if ((*str == 'Z') || (*str == '-') || (*str == '+')) {
         *(p++) = '0';
         *(p++) = '0';
     } else {
+        /* SS (seconds) */
+        if (remaining < 2)
+            return 0;
         *(p++) = *(str++);
         *(p++) = *(str++);
-        /* Skip any fractional seconds... */
-        if (*str == '.') {
+        remaining -= 2;
+        /*
+         * Skip any (up to three) fractional seconds...
+         * TODO(emilia): in RFC5280, fractional seconds are forbidden.
+         * Can we just kill them altogether?
+         */
+        if (remaining && *str == '.') {
             str++;
-            while ((*str >= '0') && (*str <= '9'))
-                str++;
+            remaining--;
+            for (i = 0; i < 3 && remaining; i++, str++, remaining--) {
+                if (*str < '0' || *str > '9')
+                    break;
+            }
         }
 
     }
     *(p++) = 'Z';
     *(p++) = '\0';
 
-    if (*str == 'Z')
+    /* We now need either a terminating 'Z' or an offset. */
+    if (!remaining)
+        return 0;
+    if (*str == 'Z') {
+        if (remaining != 1)
+            return 0;
         offset = 0;
-    else {
+    } else {
+        /* (+-)HHMM */
         if ((*str != '+') && (*str != '-'))
+            return 0;
+        /* Historical behaviour: the (+-)hhmm offset is forbidden in RFC5280. */
+        if (remaining != 5)
+            return 0;
+        if (str[1] < '0' || str[1] > '9' || str[2] < '0' || str[2] > '9' ||
+            str[3] < '0' || str[3] > '9' || str[4] < '0' || str[4] > '9')
             return 0;
         offset = ((str[1] - '0') * 10 + (str[2] - '0')) * 60;
         offset += (str[3] - '0') * 10 + (str[4] - '0');
```
