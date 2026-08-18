# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1963_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1963_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-27 of the vulnerable file.

/*
 ** Generic functions which are not dependent on ApexCharts
 */

class Utils {
  static bind(fn, me) {
    return function() {
      return fn.apply(me, arguments)
    }
  }

  static isObject(item) {
    return (
      item && typeof item === 'object' && !Array.isArray(item) && item != null
    )
  }

  static listToArray(list) {
    let i,
      array = []
    for (i = 0; i < list.length; i++) {
      array[i] = list[i]
    }
    return array
  }

  // to extend defaults with user options
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,7 @@
 
 class Utils {
   static bind(fn, me) {
-    return function() {
+    return function () {
       return fn.apply(me, arguments)
     }
   }
@@ -28,8 +28,8 @@
   // credit: http://stackoverflow.com/questions/27936772/deep-object-merging-in-es6-es7#answer-34749873
   static extend(target, source) {
     if (typeof Object.assign !== 'function') {
-      ;(function() {
-        Object.assign = function(target) {
+      ; (function () {
+        Object.assign = function (target) {
           'use strict'
           // We must check against these specific cases.
           if (target === undefined || target === null) {
@@ -218,9 +218,9 @@
     )
     return rgb && rgb.length === 4
       ? '#' +
-          ('0' + parseInt(rgb[1], 10).toString(16)).slice(-2) +
-          ('0' + parseInt(rgb[2], 10).toString(16)).slice(-2) +
-          ('0' + parseInt(rgb[3], 10).toString(16)).slice(-2)
+      ('0' + parseInt(rgb[1], 10).toString(16)).slice(-2) +
+      ('0' + parseInt(rgb[2], 10).toString(16)).slice(-2) +
+      ('0' + parseInt(rgb[3], 10).toString(16)).slice(-2)
       : ''
   }
 
@@ -380,6 +380,19 @@
     // other browser
     return false
   }
+
+  /**
+   * Sanitize dangerous characters in the string to prevent Cross-Site Scripting
+   * @param {string}
+   * string - String to sanitize
+   */
+  static sanitizeDom(string) {
+    return string
+      .replace(/\&/g, '&amp;')
+      .replace(/\</g, '&lt;')
+      .replace(/\>/g, '&gt;')
+      .replace(/\"/g, '&quot;')
+  }
 }
 
 export default Utils
```
