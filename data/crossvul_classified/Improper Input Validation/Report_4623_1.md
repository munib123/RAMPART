# CrossVul Fix Pair: Improper Input Validation in json
**Pair ID:** 4623_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4623_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```json
Lines 1-24 of the vulnerable file.

{
  "name": "connie-lang",
  "description": "Configuration language for connie",
  "version": "0.1.0",
  "homepage": "https://github.com/mattinsler/connie-lang",
  "repository": {
    "type": "git",
    "url": "git://github.com/mattinsler/connie-lang.git"
  },
  "bugs": {
    "url": "https://github.com/mattinsler/connie-lang/issues"
  },
  "main": "lib/connie-lang",
  "scripts": {
    "test": "mocha"
  },
  "engines": {
    "node": ">= 0.10.0"
  },
  "dependencies": {
    "lodash.isplainobject": "2.4.1"
  },
  "devDependencies": {
    "mocha": "2.0.1"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 {
   "name": "connie-lang",
   "description": "Configuration language for connie",
-  "version": "0.1.0",
+  "version": "0.1.1",
   "homepage": "https://github.com/mattinsler/connie-lang",
   "repository": {
     "type": "git",
@@ -23,5 +23,8 @@
   "devDependencies": {
     "mocha": "2.0.1"
   },
-  "keywords": ["configuration", "connie"]
+  "keywords": [
+    "configuration",
+    "connie"
+  ]
 }
```
