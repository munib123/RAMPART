# CrossVul Fix Pair: Improper Input Validation in json
**Pair ID:** 1105_6
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1105_6`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "slp-validate",
  "version": "1.0.0",
  "description": "SLP transaction validator",
  "main": "index.js",
  "files": [
    "index.ts",
    "lib/*.js",
    "lib/*.ts",
    "dist/"
  ],
  "scripts": {
    "test": "tsc && mocha",
    "build": "tsc && mkdirp dist && browserify index.js --standalone slpvalidate > dist/slpvalidate.js && uglifyjs dist/slpvalidate.js --compress > dist/slpvalidate.min.js"
  },
  "author": "James Cramer",
  "license": "ISC",
  "dependencies": {
    "big.js": "5.2.2",
    "@types/big.js": "^4.0.5",
    "@types/node": "^12.7.5"
  },
  "devDependencies": {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "slp-validate",
-  "version": "1.0.0",
+  "version": "1.0.1",
   "description": "SLP transaction validator",
   "main": "index.js",
   "files": [
@@ -29,6 +29,8 @@
     "grpc-slp-graphsearch-node": "^0.0.1",
     "browserify": "^16.2.2",
     "uglify-es": "^3.3.9",
-    "mkdirp": "^0.5.1"
+    "mkdirp": "^0.5.1",
+    "typescript-tslint-plugin": "^0.5.4",
+    "typescript": "^3.6.4"
   }
 }
```
