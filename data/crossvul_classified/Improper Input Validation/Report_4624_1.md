# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4624_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4624_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 1-30 of the vulnerable file.

/**
 * Based on Kendo UI Core expression code <https://github.com/telerik/kendo-ui-core#license-information>
 */
'use strict'

function Cache(maxSize) {
  this._maxSize = maxSize
  this.clear()
}
Cache.prototype.clear = function() {
  this._size = 0
  this._values = Object.create(null)
}
Cache.prototype.get = function(key) {
  return this._values[key]
}
Cache.prototype.set = function(key, value) {
  this._size >= this._maxSize && this.clear()
  if (!(key in this._values)) this._size++

  return (this._values[key] = value)
}

var SPLIT_REGEX = /[^.^\]^[]+|(?=\[\]|\.\.)/g,
  DIGIT_REGEX = /^\d+$/,
  LEAD_DIGIT_REGEX = /^\d/,
  SPEC_CHAR_REGEX = /[~`!#$%\^&*+=\-\[\]\\';,/{}|\\":<>\?]/g,
  CLEAN_QUOTES_REGEX = /^\s*(['"]?)(.*?)(\1)\s*$/,
  MAX_CACHE_SIZE = 512

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,14 +7,14 @@
   this._maxSize = maxSize
   this.clear()
 }
-Cache.prototype.clear = function() {
+Cache.prototype.clear = function () {
   this._size = 0
   this._values = Object.create(null)
 }
-Cache.prototype.get = function(key) {
+Cache.prototype.get = function (key) {
   return this._values[key]
 }
-Cache.prototype.set = function(key, value) {
+Cache.prototype.set = function (key, value) {
   this._size >= this._maxSize && this.clear()
   if (!(key in this._values)) this._size++
 
@@ -41,15 +41,26 @@
 
   normalizePath: normalizePath,
 
-  setter: function(path) {
+  setter: function (path) {
     var parts = normalizePath(path)
 
     return (
       setCache.get(path) ||
-      setCache.set(path, function setter(data, value) {
-        var index = 0,
-          len = parts.length
+      setCache.set(path, function setter(obj, value) {
+        var index = 0
+        var len = parts.length
+        var data = obj
+
         while (index < len - 1) {
+          let part = parts[index]
+          if (
+            part === '__proto__' ||
+            part === 'constructor' ||
+            part === 'prototype'
+          ) {
+            return obj
+          }
+
           data = data[parts[index++]]
         }
         data[parts[index]] = value
@@ -57,7 +68,7 @@
     )
   },
 
-  getter: function(path, safe) {
+  getter: function (path, safe) {
     var parts = normalizePath(path)
     return (
       getCache.get(path) ||
@@ -73,8 +84,8 @@
     )
   },
 
-  join: function(segments) {
-    return segments.reduce(function(path, part) {
+  join: function (segments) {
+    return segments.reduce(function (path, part) {
       return (
         path +
         (isQuoted(part) || DIGIT_REGEX.test(part)
@@ -84,9 +95,9 @@
     }, '')
   },
 
-  forEach: function(path, cb, thisArg) {
+  forEach: function (path, cb, thisArg) {
     forEach(Array.isArray(path) ? path : split(path), cb, thisArg)
-  }
+  },
 }
 
 function normalizePath(path) {
@@ -94,7 +105,7 @@
     pathCache.get(path) ||
     pathCache.set(
       path,
-      split(path).map(function(part) {
+      split(path).map(function (part) {
         return part.replace(CLEAN_QUOTES_REGEX, '$2')
       })
     )
```
