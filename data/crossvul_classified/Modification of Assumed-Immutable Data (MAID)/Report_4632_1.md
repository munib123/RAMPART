# CrossVul Fix Pair: Improperly Controlled Modification of Dynamically-Determined Object Attributes in javascript
**Pair ID:** 4632_1
**Vulnerability Class:** Modification of Assumed-Immutable Data (MAID)
**CWE:** CWE-915
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4632_1`)

## Vulnerability Information & PoC

## Description
Improperly Controlled Modification of Dynamically-Determined Object Attributes - If the object contains attributes that were only intended for internal use, then their unexpected modification could lead to a vulnerability.

## Vulnerable Code
```javascript
Lines 69-109 of the vulnerable file.

    if (hasOwnProperty(b, prop)) {
      a[prop] = b[prop]
    }
  }
  return a
}

/**
 * Deep extend an object a with the properties of object b
 * @param {Object} a
 * @param {Object} b
 * @returns {Object}
 */
export function deepExtend (a, b) {
  // TODO: add support for Arrays to deepExtend
  if (Array.isArray(b)) {
    throw new TypeError('Arrays are not supported by deepExtend')
  }

  for (const prop in b) {
    if (hasOwnProperty(b, prop)) {
      if (b[prop] && b[prop].constructor === Object) {
        if (a[prop] === undefined) {
          a[prop] = {}
        }
        if (a[prop] && a[prop].constructor === Object) {
          deepExtend(a[prop], b[prop])
        } else {
          a[prop] = b[prop]
        }
      } else if (Array.isArray(b[prop])) {
        throw new TypeError('Arrays are not supported by deepExtend')
      } else {
        a[prop] = b[prop]
      }
    }
  }
  return a
}

/**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -86,7 +86,9 @@
   }
 
   for (const prop in b) {
-    if (hasOwnProperty(b, prop)) {
+    // We check against prop not being in Object.prototype or Function.prototype
+    // to prevent polluting for example Object.__proto__.
+    if (hasOwnProperty(b, prop) && !(prop in Object.prototype) && !(prop in Function.prototype)) {
       if (b[prop] && b[prop].constructor === Object) {
         if (a[prop] === undefined) {
           a[prop] = {}
```
