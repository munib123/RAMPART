# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4440_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4440_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 1-31 of the vulnerable file.

var indexFalse,
    indexTrue,
    indexer,
    reduce,
    add,
    has,
    get,
    set;

function indexer(set) {
    return function(obj, i) {
        "use strict";
        try {
            if (obj && i && obj.hasOwnProperty(i)) {
                return obj[i];
            } else if (obj && i && set) {
                obj[i] = {};
                return obj[i];
            }
            return;
        } catch(ex) {
            console.error(ex);
            return;
        }
    };
}

indexTrue = indexer(true);
indexFalse = indexer(false);

function reduce(obj, str) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,7 +8,7 @@
     set;
 
 function indexer(set) {
-    return function(obj, i) {
+    return function (obj, i) {
         "use strict";
         try {
             if (obj && i && obj.hasOwnProperty(i)) {
@@ -18,7 +18,7 @@
                 return obj[i];
             }
             return;
-        } catch(ex) {
+        } catch (ex) {
             console.error(ex);
             return;
         }
@@ -31,15 +31,15 @@
 function reduce(obj, str) {
     "use strict";
     try {
-        if ( typeof str !== "string") {
+        if (typeof str !== "string") {
             return;
         }
-        if ( typeof obj !== "object") {
+        if (typeof obj !== "object") {
             return;
         }
         return str.split('.').reduce(indexFalse, obj);
 
-    } catch(ex) {
+    } catch (ex) {
         console.error(ex);
         return;
     }
@@ -49,21 +49,26 @@
 function add(obj, str, val) {
     "use strict";
     try {
-        if ( typeof str !== "string") {
+        if (typeof str !== "string") {
             return;
         }
-        if ( typeof obj !== "object") {
+        if (str.indexOf('__proto__') != -1) {
+            throw "cannot modify prototype property";
+        }
+        if (typeof obj !== "object") {
             return;
         }
         if (!val) {
             return;
         }
         var items = str.split('.');
+        console.log(str);
         var initial = items.slice(0, items.length - 1);
         var last = items.slice(items.length - 1);
         var test = initial.reduce(indexTrue, obj);
         test[last] = val;
-    } catch(ex) {
+
+    } catch (ex) {
         console.error(ex);
         return;
     }
@@ -73,11 +78,11 @@
     "use strict";
     try {
         var test = reduce(target, path);
-        if ( typeof test !== "undefined") {
+        if (typeof test !== "undefined") {
             return true;
         }
         return false;
-    } catch(ex) {
+    } catch (ex) {
         console.error(ex);
         return;
     }
@@ -87,7 +92,7 @@
     "use strict";
     try {
         return reduce(target, path);
-    } catch(ex) {
+    } catch (ex) {
         console.error(ex);
         return;
     }
@@ -97,7 +102,7 @@
     "use strict";
     try {
         return add(target, path, val);
-    } catch(ex) {
+    } catch (ex) {
         console.error(ex);
         return;
     }
```
