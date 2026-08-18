# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 784_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `784_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 1-23 of the vulnerable file.

import isArray from './isArray';
import isObject from './isObject';

export function mergeConfig(...configs) {
  return configs.reduce((out, source) => {
    for (var key in source) {
      if (key === 'signals') {
        // for signals, we merge the signals arrays
        // source signals take precedence over
        // existing signals with the same name
        out.signals = mergeNamed(out.signals, source.signals);
      } else {
        // otherwise, merge objects subject to recursion constraints
        // for legend block, recurse for the layout entry only
        // for style block, recurse for all properties
        // otherwise, no recursion: objects overwrite, no merging
        var r = key === 'legend' ? {'layout': 1}
          : key === 'style' ? true
          : null;
        writeConfig(out, key, source[key], r);
      }
    }
    return out;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,7 @@
 import isArray from './isArray';
 import isObject from './isObject';
+
+const isLegalKey = key => key !== '__proto__';
 
 export function mergeConfig(...configs) {
   return configs.reduce((out, source) => {
@@ -14,7 +16,7 @@
         // for legend block, recurse for the layout entry only
         // for style block, recurse for all properties
         // otherwise, no recursion: objects overwrite, no merging
-        var r = key === 'legend' ? {'layout': 1}
+        var r = key === 'legend' ? {layout: 1}
           : key === 'style' ? true
           : null;
         writeConfig(out, key, source[key], r);
@@ -25,13 +27,15 @@
 }
 
 export function writeConfig(output, key, value, recurse) {
+  if (!isLegalKey(key)) return;
+
   var k, o;
   if (isObject(value) && !isArray(value)) {
     o = isObject(output[key]) ? output[key] : (output[key] = {});
     for (k in value) {
       if (recurse && (recurse === true || recurse[k])) {
         writeConfig(o, k, value[k]);
-      } else {
+      } else if (isLegalKey(k)) {
         o[k] = value[k];
       }
     }
```
