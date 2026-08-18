# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4624_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4624_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 1-31 of the vulnerable file.

var { Cache, normalizePath, split, forEach } = require('./')

var setCache = new Cache(512),
  getCache = new Cache(512)

function makeSafe(path, param) {
  var result = param,
    parts = split(path),
    isLast

  forEach(parts, function(part, isBracket, isArray, idx, parts) {
    isLast = idx === parts.length - 1

    part = isBracket || isArray ? '[' + part + ']' : '.' + part

    result += part + (!isLast ? ' || {})' : ')')
  })

  return new Array(parts.length + 1).join('(') + result
}

function expr(expression, safe, param) {
  expression = expression || ''

  if (typeof safe === 'string') {
    param = safe
    safe = false
  }

  param = param || 'data'

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,7 +8,7 @@
     parts = split(path),
     isLast
 
-  forEach(parts, function(part, isBracket, isArray, idx, parts) {
+  forEach(parts, function (part, isBracket, isArray, idx, parts) {
     isLast = idx === parts.length - 1
 
     part = isBracket || isArray ? '[' + part + ']' : '.' + part
@@ -36,7 +36,15 @@
 
 module.exports = {
   expr,
-  setter: function(path) {
+  setter: function (path) {
+    if (
+      path.indexOf('__proto__') !== -1 ||
+      path.indexOf('constructor') !== -1 ||
+      path.indexOf('prototype') !== -1
+    ) {
+      return (obj) => obj
+    }
+
     return (
       setCache.get(path) ||
       setCache.set(
@@ -46,7 +54,7 @@
     )
   },
 
-  getter: function(path, safe) {
+  getter: function (path, safe) {
     var key = path + '_' + safe
     return (
       getCache.get(key) ||
@@ -55,5 +63,5 @@
         new Function('data', 'return ' + expr(path, safe, 'data'))
       )
     )
-  }
+  },
 }
```
