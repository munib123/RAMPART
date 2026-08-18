# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4249_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4249_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 23-63 of the vulnerable file.

            console.warn('Warning: JPV. ? and ! short tag operators are deprecated, please use "or" or "not operators instead"');
        }
        if (name === 'tag') {
            console.warn('Warning: JPV. Avoid using deprecated "{}" short tags');
        }
        warnings[name] = true;
    }
}

function comparePattern (value, pattern) {
    for (let i = 0; i < patterns.length; i++) {
        const match = pattern.match(
            new RegExp(`^${patterns[i].pattern}$`, patterns[i].flag || '')
        );
        if (match) {
            return patterns[i].onMatch(String(value), match);
        }
    }
    console.log(`Unrecognized Pattern: ${pattern}`);
    throw new Error('Invalid Pattern');
}

/**
 * OR operator
 * @param patterns
 */
module.exports.or = function or (patterns) {
    return new JpvObject('or', Array.prototype.slice.call(arguments));
};

/**
 * AND operator
 * @param patterns
 */

module.exports.and = function and (patterns) {
    return new JpvObject('and', Array.prototype.slice.call(arguments));
};

/**
 * NOT operator
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,6 +43,27 @@
 }
 
 /**
+ * Custom Is Array
+ * @param value
+ * @returns boolean
+ */
+function isArray (value) {
+    if (Object.prototype.hasOwnProperty.call(Array, 'isArray')) {
+        return Array.isArray(value);
+    }
+    if (typeof value !== 'object') {
+        return false;
+    }
+    if (Object.prototype.toString.call(value) !== '[object Array]') {
+        return false;
+    }
+    if (!(value instanceof Array)) {
+        return false;
+    }
+    return true;
+}
+
+/**
  * OR operator
  * @param patterns
  */
@@ -120,20 +141,19 @@
     const res = (result) => {
         let val = '';
         if (!pattern || ((typeof pattern !== 'object') && (typeof pattern !== 'string') && typeof pattern !== 'function')) {
-            val = String(pattern)
+            val = String(pattern);
         } else if (pattern.constructor === JpvObject) {
             val = `operator "${pattern.type}": ${JSON.stringify(pattern.value)}`;
         } else {
-            JSON.stringify(pattern)
-        }
-
+            JSON.stringify(pattern);
+        }
 
         if (typeof pattern === 'function') {
             val = pattern.toString();
         }
         if (!result && options && options.debug) {
             options.logger(`error - the value of: {${options.deepLog.join('.')}: ` +
-            `${String(value)}} not matched with: ${val}`);
+                `${String(value)}} not matched with: ${val}`);
         }
         return result;
     };
@@ -270,6 +290,10 @@
 
     // pattern = object
     if (typeof pattern === 'object') {
+        if (isArray(pattern)) {
+            return res(isArray(value));
+        }
+
         if (value !== null) {
             return res(value.constructor === pattern.constructor);
         }
@@ -393,13 +417,13 @@
     * Iterate through value
     * */
     for (const property in value) {
-        if (value.hasOwnProperty(property)) {
+        if (Object.prototype.hasOwnProperty.call(value, String(property))) {
             const level = push(options, property, value.constructor);
             valid = (() => {
                 /*
                 * When missing pattern
                 * */
-                if (!pattern.hasOwnProperty(property)) {
+                if (!Object.prototype.hasOwnProperty.call(pattern, String(property))) {
                     return (valid = cb(value[property], undefined, options));
                 }
 
@@ -411,8 +435,8 @@
                 /*
                 * iterate if pattern is an Array
                 * */
-                if ((pattern[property].constructor === Array) && (pattern[property].length > 0)) {
-                    if (value[property].constructor !== Array) {
+                if ((isArray(pattern[property])) && (pattern[property].length > 0)) {
+                    if (!isArray(value[property])) {
                         return (valid = cb(value[property], pattern[property], options));
                     }
                     for (let i = 0; i < value[property].length; i++) {
```
