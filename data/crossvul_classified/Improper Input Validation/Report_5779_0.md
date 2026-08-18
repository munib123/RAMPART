# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 5779_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5779_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 1-14 of the vulnerable file.

/* vim: set expandtab sw=4 ts=4 sts=4: */
/**
 * Conditionally included if third-party framing is not allowed
 *
 */

try {
    if (top != self) {
        top.location.href = self.location.href;
    }
} catch(e) {
    alert("Redirecting... (error: " + e);
    top.location.href = self.location.href;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,14 +1,9 @@
 /* vim: set expandtab sw=4 ts=4 sts=4: */
 /**
- * Conditionally included if third-party framing is not allowed
- *
+ * Conditionally included if framing is not allowed
  */
-
-try {
-    if (top != self) {
-        top.location.href = self.location.href;
-    }
-} catch(e) {
-    alert("Redirecting... (error: " + e);
-    top.location.href = self.location.href;
+if(self == top) {
+    document.documentElement.style.display = 'block' ;
+} else {
+    top.location = self.location ;
 }
```
