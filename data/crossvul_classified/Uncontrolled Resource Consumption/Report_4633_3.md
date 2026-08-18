# CrossVul Fix Pair: Uncontrolled Resource Consumption in typescript
**Pair ID:** 4633_3
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4633_3`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```typescript
Lines 1-17 of the vulnerable file.

/**
 * Remove undefined value
 * @param obj
 */

export function cleanObject(obj: any): any {
  return Object.entries(obj).reduce(
    (obj, [key, value]) =>
      value === undefined
        ? obj
        : {
            ...obj,
            [key]: value
          },
    {}
  );
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,17 +1,19 @@
+import {isProtectedKey} from "./isProtectedKey";
 /**
  * Remove undefined value
  * @param obj
  */
+export function cleanObject(obj: any): any {
+  return Object.entries(obj).reduce((obj, [key, value]) => {
+    if (isProtectedKey(key)) {
+      return obj;
+    }
 
-export function cleanObject(obj: any): any {
-  return Object.entries(obj).reduce(
-    (obj, [key, value]) =>
-      value === undefined
-        ? obj
-        : {
-            ...obj,
-            [key]: value
-          },
-    {}
-  );
+    return value === undefined
+      ? obj
+      : {
+          ...obj,
+          [key]: value
+        };
+  }, {});
 }
```
