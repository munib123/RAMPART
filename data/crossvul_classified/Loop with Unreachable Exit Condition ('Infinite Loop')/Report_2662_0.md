# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 2662_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2662_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 464-504 of the vulnerable file.


    if (len == 0)
        goto trunc;
    ND_TCHECK(*bp);
    too_large = 0;
    neg = 0;
    if (*bp == '-') {
        neg = 1;
        bp++;
        len--;
    }
    result = 0;
    saw_digit = 0;

    for (;;) {
        if (len == 0)
            goto trunc;
        ND_TCHECK(*bp);
        c = *bp;
        if (!(c >= '0' && c <= '9')) {
            if (!saw_digit)
                goto invalid;
            break;
        }
        c -= '0';
        if (result > (INT_MAX / 10)) {
            /* This will overflow an int when we multiply it by 10. */
            too_large = 1;
        } else {
            result *= 10;
            if (result == INT_MAX && c > (INT_MAX % 10)) {
                /* This will overflow an int when we add c */
                too_large = 1;
            } else
                result += c;
        }
        bp++;
        len--;
        saw_digit = 1;
    }
    if (!saw_digit)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -481,8 +481,10 @@
         ND_TCHECK(*bp);
         c = *bp;
         if (!(c >= '0' && c <= '9')) {
-            if (!saw_digit)
+            if (!saw_digit) {
+                bp++;
                 goto invalid;
+            }
             break;
         }
         c -= '0';
@@ -510,15 +512,19 @@
     if (len == 0)
         goto trunc;
     ND_TCHECK(*bp);
-    if (*bp != '\r')
+    if (*bp != '\r') {
+        bp++;
         goto invalid;
+    }
     bp++;
     len--;
     if (len == 0)
         goto trunc;
     ND_TCHECK(*bp);
-    if (*bp != '\n')
+    if (*bp != '\n') {
+        bp++;
         goto invalid;
+    }
     bp++;
     len--;
     *endp = bp;
@@ -531,8 +537,10 @@
     return (too_large ? -3 : result);
 
 trunc:
+    *endp = bp;
     return (-2);
 
 invalid:
+    *endp = bp;
     return (-5);
 }
```
