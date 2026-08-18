# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 559_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `559_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 1-39 of the vulnerable file.

/*!
 * defaults-deep <https://github.com/jonschlinkert/defaults-deep>
 *
 * Copyright (c) 2014-2015, Jon Schlinkert.
 * Licensed under the MIT License.
 */

'use strict';

var lazy = require('lazy-cache')(require);
lazy('is-extendable', 'isObject');
lazy('for-own', 'forOwn');

function defaultsDeep(target, objects) {
  target = target || {};

  function copy(target, current) {
    lazy.forOwn(current, function (value, key) {
      var val = target[key];
      // add the missing property, or allow a null property to be updated
      if (val == null) {
        target[key] = value;
      } else if (lazy.isObject(val) && lazy.isObject(value)) {
        defaultsDeep(val, value);
      }
    });
  }

  var len = arguments.length, i = 0;
  while (i < len) {
    var obj = arguments[i++];
    if (obj) {
      copy(target, obj);
    }
  }
  return target;
};

/**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,6 +16,10 @@
 
   function copy(target, current) {
     lazy.forOwn(current, function (value, key) {
+      if (key === '__proto__') {
+        return;
+      }
+
       var val = target[key];
       // add the missing property, or allow a null property to be updated
       if (val == null) {
```
