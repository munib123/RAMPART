# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 1003_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1003_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 550-586 of the vulnerable file.


Sfdouble_t sh_arith(Shell_t *shp, const char *str) { return sh_strnum(shp, str, NULL, 1); }

void *sh_arithcomp(Shell_t *shp, char *str) {
    const char *ptr = str;
    Arith_t *ep;

    ep = arith_compile(shp, str, (char **)&ptr, arith, ARITH_COMP | 1);
    if (*ptr) errormsg(SH_DICT, ERROR_exit(1), e_lexbadchar, *ptr, str);
    return ep;
}

// Convert number defined by string to a Sfdouble_t.
// Ptr is set to the last character processed.
// If mode>0, an error will be fatal with value <mode>.
Sfdouble_t sh_strnum(Shell_t *shp, const char *str, char **ptr, int mode) {
    Sfdouble_t d;
    char *last;

    if (*str == 0) {
        if (ptr) *ptr = (char *)str;
        return 0;
    }
    errno = 0;
    d = number(str, &last, shp->inarith ? 0 : 10, NULL);
    if (*last) {
        if (*last != '.' || last[1] != '.') {
            d = strval(shp, str, &last, arith, mode);
            Varsubscript = true;
        }
        if (!ptr && *last && mode > 0) errormsg(SH_DICT, ERROR_exit(1), e_lexbadchar, *last, str);
    } else if (!d && *str == '-') {
        d = -0.0;
    }
    if (ptr) *ptr = last;
    return d;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -567,19 +567,32 @@
     char *last;
 
     if (*str == 0) {
-        if (ptr) *ptr = (char *)str;
-        return 0;
-    }
-    errno = 0;
-    d = number(str, &last, shp->inarith ? 0 : 10, NULL);
-    if (*last) {
-        if (*last != '.' || last[1] != '.') {
-            d = strval(shp, str, &last, arith, mode);
-            Varsubscript = true;
-        }
-        if (!ptr && *last && mode > 0) errormsg(SH_DICT, ERROR_exit(1), e_lexbadchar, *last, str);
-    } else if (!d && *str == '-') {
-        d = -0.0;
+        d = 0.0;
+        last = (char *)str;
+    } else {
+        d = number(str, &last, shp->inarith ? 0 : 10, NULL);
+        if (*last && !shp->inarith && sh_isstate(shp, SH_INIT)) {
+            // This call is to handle "base#value" literals if we're importing untrusted env vars.
+            d = number(str, &last, 0, NULL);
+        }
+        if (*last) {
+            if (sh_isstate(shp, SH_INIT)) {
+                // Initializing means importing untrusted env vars. Since the string does not appear
+                // to be a recognized numeric literal give up. We can't safely call strval() since
+                // that allows arbitrary expressions which would create a security vulnerability.
+                d = 0.0;
+            } else {
+                if (*last != '.' || last[1] != '.') {
+                    d = strval(shp, str, &last, arith, mode);
+                    Varsubscript = true;
+                }
+                if (!ptr && *last && mode > 0) {
+                    errormsg(SH_DICT, ERROR_exit(1), e_lexbadchar, *last, str);
+                }
+            }
+        } else if (d == 0.0 && *str == '-') {
+            d = -0.0;
+        }
     }
     if (ptr) *ptr = last;
     return d;
```
