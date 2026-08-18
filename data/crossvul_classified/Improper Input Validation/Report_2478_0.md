# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 2478_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2478_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 1-31 of the vulnerable file.

/**
 * Set given `path`
 *
 * @param {Object} obj
 * @param {String} path
 * @param {Mixed} val
 * @return {Object}
 * @api public
 */

exports.set = function (obj, path, val) {
  var segs = path.split('.');
  var attr = segs.pop();
  var src = obj;

  for (var i = 0; i < segs.length; i++) {
    var seg = segs[i];
    obj[seg] = obj[seg] || {};
    obj = obj[seg];
  }

  obj[attr] = val;

  return src;
};

/**
 * Get given `path`
 *
 * @param {Object} obj
 * @param {String} path
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,18 +8,21 @@
  * @api public
  */
 
-exports.set = function (obj, path, val) {
+exports.set = function(obj, path, val) {
   var segs = path.split('.');
   var attr = segs.pop();
   var src = obj;
 
   for (var i = 0; i < segs.length; i++) {
     var seg = segs[i];
+    if (!isSafe(obj, seg)) return src;
     obj[seg] = obj[seg] || {};
     obj = obj[seg];
   }
 
-  obj[attr] = val;
+  if (isSafe(obj, attr)) {
+    obj[attr] = val;
+  }
 
   return src;
 };
@@ -33,7 +36,7 @@
  * @api public
  */
 
-exports.get = function (obj, path) {
+exports.get = function(obj, path) {
   var segs = path.split('.');
   var attr = segs.pop();
 
@@ -55,19 +58,42 @@
  * @api public
  */
 
-exports.delete = function (obj, path) {
+exports.delete = function(obj, path) {
   var segs = path.split('.');
   var attr = segs.pop();
 
   for (var i = 0; i < segs.length; i++) {
     var seg = segs[i];
     if (!obj[seg]) return;
+    if (!isSafe(obj, seg)) return;
     obj = obj[seg];
   }
 
+  if (!isSafe(obj, attr)) return;
+
   if (Array.isArray(obj)) {
-    obj.splice(path, 1);
+    obj.splice(attr, 1);
   } else {
     delete obj[attr];
   }
 };
+
+function isSafe(obj, prop) {
+  if (isObject(obj)) {
+    return obj[prop] === undefined || hasOwnProperty(obj, prop);
+  }
+
+  if (Array.isArray(obj)) {
+    return !isNaN(parseInt(prop, 10));
+  }
+
+  return false;
+}
+
+function hasOwnProperty(obj, prop) {
+  return Object.prototype.hasOwnProperty.call(obj, prop);
+}
+
+function isObject(obj) {
+  return Object.prototype.toString.call(obj) === '[object Object]';
+}
```
