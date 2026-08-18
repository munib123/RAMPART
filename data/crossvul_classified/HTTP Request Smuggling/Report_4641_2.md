# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in javascript
**Pair ID:** 4641_2
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4641_2`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```javascript
Lines 1-10 of the vulnerable file.

'use strict'

const SemVerStore = require('semver-store')

module.exports = {
  storage: SemVerStore,
  deriveVersion: function (req, ctx) {
    return req.headers['accept-version']
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,9 +2,20 @@
 
 const SemVerStore = require('semver-store')
 
-module.exports = {
-  storage: SemVerStore,
-  deriveVersion: function (req, ctx) {
-    return req.headers['accept-version']
+function build (enabled) {
+  if (enabled) {
+    return {
+      storage: SemVerStore,
+      deriveVersion: function (req, ctx) {
+        return req.headers['accept-version']
+      }
+    }
+  }
+  return {
+    storage: SemVerStore,
+    deriveVersion: function (req, ctx) {},
+    disabled: true
   }
 }
+
+module.exports = build
```
