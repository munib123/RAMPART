# CrossVul Fix Pair: Improper Input Validation in json
**Pair ID:** 4440_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4440_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "deephas",
  "version": "1.0.5",
  "description": "get, set or test for a value in a javascript object",
  "main": "deepHas.js",
  "scripts": {
    "test": "./runTests.sh"
  },
  "repository": {
    "type": "git",
    "url": "git@github.com:sharpred/deepHas.git"
  },
  "keywords": [
    "nested",
    "object",
    "key"
  ],
  "author": "Paul Ryan <paul.ryan@stepupsoftware.co.uk>",
  "license": "MIT",
  "bugs": {
    "url": "https://github.com/sharpred/deepHas/issues"
  },
  "homepage": "https://github.com/sharpred/deepHas",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "deephas",
-  "version": "1.0.5",
+  "version": "1.0.6",
   "description": "get, set or test for a value in a javascript object",
   "main": "deepHas.js",
   "scripts": {
```
