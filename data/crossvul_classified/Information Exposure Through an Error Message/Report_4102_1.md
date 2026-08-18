# CrossVul Fix Pair: Generation of Error Message Containing Sensitive Information in javascript
**Pair ID:** 4102_1
**Vulnerability Class:** Information Exposure Through an Error Message
**CWE:** CWE-209
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4102_1`)

## Vulnerability Information & PoC

## Description
Generation of Error Message Containing Sensitive Information - The sensitive information may be valuable information on its own (such as a password), or it may be useful for launching other, more serious attacks.

## Vulnerable Code
```javascript
Lines 1-35 of the vulnerable file.

var util = require('util');

/**
 * @module errors
 */
var errors = (module.exports = {});

/**
 * Given a response request error, sanitize sensitive data.
 *
 * @method    sanitizeErrorRequestData
 * @memberOf  module:errors
 */
errors.sanitizeErrorRequestData = function(error) {
  if (!error.response || !error.response.request || !error.response.request._data) {
    return error;
  }

  Object.keys(error.response.request._data).forEach(function(key) {
    if (key.toLowerCase().match('password|secret')) {
      error.response.request._data[key] = '[SANITIZED]';
    }
  });

  return error;
};

/**
 * Given an Api Error, modify the original error and sanitize
 * sensitive information using sanitizeErrorRequestData
 *
 * @method    SanitizedError
 * @memberOf  module:errors
 */
var SanitizedError = function(name, message, status, requestInfo, originalError) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,17 +12,30 @@
  * @memberOf  module:errors
  */
 errors.sanitizeErrorRequestData = function(error) {
-  if (!error.response || !error.response.request || !error.response.request._data) {
+  if (
+    !error.response ||
+    !error.response.request ||
+    (!error.response.request._data && !error.response.request._header)
+  ) {
     return error;
   }
 
-  Object.keys(error.response.request._data).forEach(function(key) {
-    if (key.toLowerCase().match('password|secret')) {
-      error.response.request._data[key] = '[SANITIZED]';
+  sanitizeErrors(error.response.request._header);
+  sanitizeErrors(error.response.request._data);
+
+  return error;
+};
+
+var sanitizeErrors = function(collection) {
+  if (!collection) {
+    return;
+  }
+
+  Object.keys(collection).forEach(function(key) {
+    if (key.toLowerCase().match('password|secret|authorization')) {
+      collection[key] = '[SANITIZED]';
     }
   });
-
-  return error;
 };
 
 /**
```
