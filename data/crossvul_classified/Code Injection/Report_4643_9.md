# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 4643_9
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4643_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 259-299 of the vulnerable file.

        logger = createDefaultLogger(levels);
    }

    levels.forEach(level => {
        response[level] = (data, message, ...args) => {
            module.exports._logFunc(logger, level, defaults, data, message, ...args);
        };
    });

    return response;
};

/**
 * Wrapper for creating a callback that either resolves or rejects a promise
 * based on input
 *
 * @param {Function} resolve Function to run if callback is called
 * @param {Function} reject Function to run if callback ends with an error
 */
module.exports.callbackPromise = (resolve, reject) =>
    function() {
        let args = Array.from(arguments);
        let err = args.shift();
        if (err) {
            reject(err);
        } else {
            resolve(...args);
        }
    };

/**
 * Resolves a String or a Buffer value for content value. Useful if the value
 * is a Stream or a file or an URL. If the value is a Stream, overwrites
 * the stream object with the resolved value (you can't stream a value twice).
 *
 * This is useful when you want to create a plugin that needs a content value,
 * for example the `html` or `text` value as a String or a Buffer but not as
 * a file path or an URL.
 *
 * @param {Object} data An object or an Array you want to resolve an element for
 * @param {String|Number} key Property name or an Array index
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -276,7 +276,7 @@
  * @param {Function} reject Function to run if callback ends with an error
  */
 module.exports.callbackPromise = (resolve, reject) =>
-    function() {
+    function () {
         let args = Array.from(arguments);
         let err = args.shift();
         if (err) {
@@ -357,7 +357,7 @@
 /**
  * Copies properties from source objects to target objects
  */
-module.exports.assign = function(/* target, ... sources */) {
+module.exports.assign = function (/* target, ... sources */) {
     let args = Array.from(arguments);
     let target = args.shift() || {};
 
@@ -489,15 +489,7 @@
 
         message = util.format(message, ...args);
         message.split(/\r?\n/).forEach(line => {
-            console.log(
-                '[%s] %s %s',
-                new Date()
-                    .toISOString()
-                    .substr(0, 19)
-                    .replace(/T/, ' '),
-                levelNames.get(level),
-                prefix + line
-            );
+            console.log('[%s] %s %s', new Date().toISOString().substr(0, 19).replace(/T/, ' '), levelNames.get(level), prefix + line);
         });
     };
 
```
