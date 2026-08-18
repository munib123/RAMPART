# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4625_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4625_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 434-474 of the vulnerable file.

    return;
  } // No path string


  if (!internalPath) {
    return;
  }

  internalPath = clean(internalPath); // Path is not a string, throw error

  if (typeof internalPath !== "string") {
    throw new Error("Path argument must be a string");
  }

  if ((0, _typeof2["default"])(obj) !== "object") {
    return;
  } // Path has no dot-notation, set key/value


  if (isNonCompositePath(internalPath)) {
    obj = decouple(obj, options);
    obj[options.transformKey(unEscape(internalPath))] = val;
    return obj;
  }

  var newObj = decouple(obj, options);
  var pathParts = split(internalPath);
  var pathPart = pathParts.shift();
  var transformedPathPart = options.transformKey(pathPart);
  var childPart = newObj[transformedPathPart];

  if ((0, _typeof2["default"])(childPart) !== "object") {
    // Create an object or array on the path
    if (String(parseInt(transformedPathPart, 10)) === transformedPathPart) {
      // This is an array index
      newObj[transformedPathPart] = [];
    } else {
      newObj[transformedPathPart] = {};
    }

    objPart = newObj[transformedPathPart];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -451,6 +451,8 @@
 
 
   if (isNonCompositePath(internalPath)) {
+    // Do not allow prototype pollution
+    if (internalPath === "__proto__") return obj;
     obj = decouple(obj, options);
     obj[options.transformKey(unEscape(internalPath))] = val;
     return obj;
@@ -459,7 +461,9 @@
   var newObj = decouple(obj, options);
   var pathParts = split(internalPath);
   var pathPart = pathParts.shift();
-  var transformedPathPart = options.transformKey(pathPart);
+  var transformedPathPart = options.transformKey(pathPart); // Do not allow prototype pollution
+
+  if (transformedPathPart === "__proto__") return obj;
   var childPart = newObj[transformedPathPart];
 
   if ((0, _typeof2["default"])(childPart) !== "object") {
@@ -519,8 +523,12 @@
   var newObj = decouple(obj, options); // Path has no dot-notation, set key/value
 
   if (isNonCompositePath(internalPath)) {
-    if (newObj.hasOwnProperty(unEscape(internalPath))) {
-      delete newObj[options.transformKey(unEscape(internalPath))];
+    var unescapedPath = unEscape(internalPath); // Do not allow prototype pollution
+
+    if (unescapedPath === "__proto__") return obj;
+
+    if (newObj.hasOwnProperty(unescapedPath)) {
+      delete newObj[options.transformKey(unescapedPath)];
       return newObj;
     }
 
@@ -530,7 +538,9 @@
 
   var pathParts = split(internalPath);
   var pathPart = pathParts.shift();
-  var transformedPathPart = options.transformKey(unEscape(pathPart));
+  var transformedPathPart = options.transformKey(unEscape(pathPart)); // Do not allow prototype pollution
+
+  if (transformedPathPart === "__proto__") return obj;
   var childPart = newObj[transformedPathPart];
 
   if (!childPart) {
@@ -618,6 +628,7 @@
   path = clean(path);
   var pathParts = split(path);
   var part = pathParts.shift();
+  if (part === "__proto__") return obj;
 
   if (pathParts.length) {
     // Generate the path part in the object if it does not already exist
@@ -671,6 +682,7 @@
   path = clean(path);
   var pathParts = split(path);
   var part = pathParts.shift();
+  if (part === "__proto__") return obj;
 
   if (pathParts.length) {
     // Generate the path part in the object if it does not already exist
```
