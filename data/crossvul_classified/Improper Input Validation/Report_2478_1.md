# CrossVul Fix Pair: Improper Input Validation in json
**Pair ID:** 2478_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2478_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```json
Lines 1-21 of the vulnerable file.

{
  "name": "@eivifj/dot",
  "publishConfig": {
    "access": "public"
  },
  "version": "1.0.2",
  "description": "Get and set object properties with dot notation",
  "main": "index.js",
  "scripts": {
    "test": "node test"
  },
  "repository": "eivindfjeldstad/dot",
  "keywords": [
    "dot",
    "notation",
    "properties",
    "object",
    "path"
  ],
  "license": "MIT"
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,7 +3,7 @@
   "publishConfig": {
     "access": "public"
   },
-  "version": "1.0.2",
+  "version": "1.0.3",
   "description": "Get and set object properties with dot notation",
   "main": "index.js",
   "scripts": {
```
