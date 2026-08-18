# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4623_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4623_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 1-24 of the vulnerable file.

var vm = require('vm');
var isPlainObject = require('lodash.isplainobject');

var getValue = function(obj, key) {
  var o = obj;
  var keys = Array.isArray(key) ? key : key.split('.');

  for (var x = 0; x < keys.length -1; ++x) {
    var k = keys[x];
    if (!o[k]) return;
    o = o[k];
  }

  return o[keys[keys.length - 1]];
};

var setValue = function(obj, key, value) {
  var o = obj;
  var keys = Array.isArray(key) ? key : key.split('.');

  for (var x = 1; x < keys.length; ++x) {
    var currentKey = keys[x];
    var lastKey = keys[x - 1];
    if (typeof(currentKey) === 'number') {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,11 +1,11 @@
 var vm = require('vm');
 var isPlainObject = require('lodash.isplainobject');
 
-var getValue = function(obj, key) {
+var getValue = function (obj, key) {
   var o = obj;
   var keys = Array.isArray(key) ? key : key.split('.');
 
-  for (var x = 0; x < keys.length -1; ++x) {
+  for (var x = 0; x < keys.length - 1; ++x) {
     var k = keys[x];
     if (!o[k]) return;
     o = o[k];
@@ -14,18 +14,22 @@
   return o[keys[keys.length - 1]];
 };
 
-var setValue = function(obj, key, value) {
+var setValue = function (obj, key, value) {
   var o = obj;
   var keys = Array.isArray(key) ? key : key.split('.');
 
   for (var x = 1; x < keys.length; ++x) {
     var currentKey = keys[x];
     var lastKey = keys[x - 1];
-    if (typeof(currentKey) === 'number') {
-      if (!o[lastKey]) { o[lastKey] = []; }
+    if (typeof currentKey === 'number') {
+      if (!o[lastKey]) {
+        o[lastKey] = [];
+      }
       o = o[lastKey];
-    } else if (typeof(currentKey) === 'string') {
-      if (!o[lastKey]) { o[lastKey] = {}; }
+    } else if (typeof currentKey === 'string') {
+      if (!o[lastKey]) {
+        o[lastKey] = {};
+      }
       o = o[lastKey];
     } else {
       throw new Error('Oopsy, key arrays should only be strings and numbers:', keys);
@@ -36,54 +40,66 @@
   return obj;
 };
 
-
 var PARSE_RX = /([^\}:]+)(:([^\}]+))?/;
 
 var EnvVarInterpreter = {
   type: '$',
-  replace: function(value, context, parseContext) {
+  replace: function (value, context, parseContext) {
     var m = PARSE_RX.exec(parseContext.value);
-    if (!m) { return value; }
+    if (!m) {
+      return value;
+    }
 
     var newValue = context.env[m[1]] || m[3] || '';
     return value.slice(0, parseContext.start) + newValue + value.slice(parseContext.end);
-  }
+  },
 };
 
 var ReferenceInterpreter = {
   type: '@',
-  replace: function(value, context, parseContext) {
+  replace: function (value, context, parseContext) {
     var m = PARSE_RX.exec(parseContext.value);
-    if (!m) { return value; }
+    if (!m) {
+      return value;
+    }
 
     var newValue = getValue(context.config, m[1]) || m[3];
-    if (value === parseContext.match) { return newValue; }
+    if (value === parseContext.match) {
+      return newValue;
+    }
     return value.slice(0, parseContext.start) + newValue + value.slice(parseContext.end);
-  }
+  },
 };
 
 var Interpreters = [ReferenceInterpreter, EnvVarInterpreter];
 
 var ConnieLang = {
   Interpreters: Interpreters,
-  InterpretersByType: Interpreters.reduce(function(o, i) {o[i.type] = i; return o;}, {}),
+  InterpretersByType: Interpreters.reduce(function (o, i) {
+    o[i.type] = i;
+    return o;
+  }, {}),
 
-  getEntries: function(config) {
+  getEntries: function (config) {
     var entries = [];
 
-    var iter = function(value, prefix) {
+    var iter = function (value, prefix) {
       if (!prefix) prefix = [];
 
       if (Array.isArray(value)) {
-        value.forEach(function(arrValue, idx) {
+        value.forEach(function (arrValue, idx) {
           iter(arrValue, prefix.concat(idx));
         });
       } else if (isPlainObject(value)) {
-        Object.keys(value).forEach(function(key) {
+        var keys = Object.keys(value);
+        if (keys.includes('__proto__') || keys.includes('constructor')) {
+          return;
+        }
+        keys.forEach(function (key) {
           iter(value[key], prefix.concat(key));
         });
       } else {
-        entries.push({key: prefix, value: value});
+        entries.push({ key: prefix, value: value });
       }
     };
 
@@ -91,8 +107,10 @@
     return entries;
   },
 
-  firstInnermostInterpreterFromValue: function(value) {
-    if (value === null || value === undefined) { return null; }
+  firstInnermostInterpreterFromValue: function (value) {
+    if (value === null || value === undefined) {
+      return null;
+    }
 
     var start = -1;
     var interpreterTypes = Object.keys(ConnieLang.InterpretersByType);
@@ -109,9 +127,9 @@
           value: value.slice(start + 2, idx),
           start: start,
           end: idx + 1,
-          replaceInValue: function(value, context) {
+          replaceInValue: function (value, context) {
             return interpreter.replace(value, context, parseContext);
-          }
+          },
         };
 
         return parseContext;
@@ -121,19 +139,19 @@
     return null;
   },
 
-  parse: function(configObj, envObj) {
+  parse: function (configObj, envObj) {
     var context = {
-      config: configObj,
-      env: envObj || process.env
+      config: Object.assign(Object.create(null), configObj),
+      env: envObj || process.env,
     };
 
     var entries = ConnieLang.getEntries(context.config);
 
     // iterate until no updates have been made
-    var digest = function() {
+    var digest = function () {
       var updated = false;
 
-      entries.forEach(function(e) {
+      entries.forEach(function (e) {
         var interpreter = ConnieLang.firstInnermostInterpreterFromValue(e.value, context);
         if (!interpreter) return;
 
@@ -147,15 +165,15 @@
       return updated;
     };
 
-    while(digest()) ;
+    while (digest());
 
     var result = {};
-    entries.forEach(function(e) {
+    entries.forEach(function (e) {
       setValue(result, e.key, e.value);
     });
 
     return result;
-  }
+  },
 };
 
 module.exports = ConnieLang;
```
