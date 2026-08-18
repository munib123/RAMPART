# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4644_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4644_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 1-30 of the vulnerable file.

"use strict";

const OBJECT = "object";

/**
 * Apply a JSON merge patch onto a document
 * https://tools.ietf.org/html/rfc7396
 * @param  {Object} doc    - JSON object document
 * @param  {Object} patch  - JSON object patch
 * @return {Object}        - JSON object document
 */
module.exports = function apply(doc, patch) {
  if (typeof patch !== OBJECT || patch === null || Array.isArray(patch)) {
    return patch;
  }

  if (typeof doc !== OBJECT || doc === null || Array.isArray(doc)) {
    doc = Object.create(null);
  }

  const keys = Object.keys(patch);
  for (const key of keys) {
    const v = patch[key];
    if (v === null) {
      delete doc[key];
      continue;
    }
    doc[key] = apply(doc[key], v);
  }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,21 +5,29 @@
 /**
  * Apply a JSON merge patch onto a document
  * https://tools.ietf.org/html/rfc7396
- * @param  {Object} doc    - JSON object document
- * @param  {Object} patch  - JSON object patch
- * @return {Object}        - JSON object document
+ * @param  {Object}  doc                       - JSON object document
+ * @param  {Object}  patch                     - JSON object patch
+ * @param  {Object}  [options]                 - options
+ * @param  {Boolean} [options.pollute=false]   - Allow prototype pollution - throw otherwise
+ * @param  {Object}  [options.proto=null]      - Prototype to use for object creation
+ * @return {Object}                            - JSON object document
  */
-module.exports = function apply(doc, patch) {
+module.exports = function apply(doc, patch, options) {
   if (typeof patch !== OBJECT || patch === null || Array.isArray(patch)) {
     return patch;
   }
 
+  options = options || Object.create(null);
+
   if (typeof doc !== OBJECT || doc === null || Array.isArray(doc)) {
-    doc = Object.create(null);
+    doc = Object.create(options.proto || null);
   }
 
   const keys = Object.keys(patch);
   for (const key of keys) {
+    if (options.pollute !== true && key === "__proto__") {
+      throw new Error("Prototype pollution attempt");
+    }
     const v = patch[key];
     if (v === null) {
       delete doc[key];
```
