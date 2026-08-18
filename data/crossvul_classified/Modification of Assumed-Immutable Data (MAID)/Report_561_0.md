# CrossVul Fix Pair: Modification of Assumed-Immutable Data (MAID) in javascript
**Pair ID:** 561_0
**Vulnerability Class:** Modification of Assumed-Immutable Data (MAID)
**CWE:** CWE-471
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `561_0`)

## Vulnerability Information & PoC

## Description
Modification of Assumed-Immutable Data (MAID) - This occurs when a particular input is critical enough to the functioning of the application that it should not be modifiable at all, but it is.

## Vulnerable Code
```javascript
Lines 98-138 of the vulnerable file.

    if (!source) {
        return target;
    }

    if (Array.isArray(source)) {
        exports.assert(Array.isArray(target), 'Cannot merge array onto an object');
        if (isMergeArrays === false) {                                                  // isMergeArrays defaults to true
            target.length = 0;                                                          // Must not change target assignment
        }

        for (let i = 0; i < source.length; ++i) {
            target.push(exports.clone(source[i]));
        }

        return target;
    }

    const keys = Object.keys(source);
    for (let i = 0; i < keys.length; ++i) {
        const key = keys[i];
        const value = source[key];
        if (value &&
            typeof value === 'object') {

            if (!target[key] ||
                typeof target[key] !== 'object' ||
                (Array.isArray(target[key]) !== Array.isArray(value)) ||
                value instanceof Date ||
                Buffer.isBuffer(value) ||
                value instanceof RegExp) {

                target[key] = exports.clone(value);
            }
            else {
                exports.merge(target[key], value, isNullOverride, isMergeArrays);
            }
        }
        else {
            if (value !== null &&
                value !== undefined) {                              // Explicit to preserve empty strings

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -115,6 +115,10 @@
     const keys = Object.keys(source);
     for (let i = 0; i < keys.length; ++i) {
         const key = keys[i];
+        if (key === '__proto__') {
+            continue;
+        }
+
         const value = source[key];
         if (value &&
             typeof value === 'object') {
```
