# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in json
**Pair ID:** 782_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `782_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "compile-sass",
  "version": "1.0.4",
  "description": "A module to compile SASS on-the-fly and/or save it to CSS files",
  "main": "dist/index.js",
  "typings": "dist/index.d.ts",
  "scripts": {
    "test:watch": "NODE_ENV=test jest --watch --verbose .",
    "test": "NODE_ENV=test jest .",
    "build": "tsc",
    "start": "tsc -w"
  },
  "repository": {
    "type": "git",
    "url": "git+https://github.com/eiskalteschatten/compile-sass.git"
  },
  "files": [
    "dist"
  ],
  "keywords": [
    "sass",
    "scss",
    "css",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "compile-sass",
-  "version": "1.0.4",
+  "version": "1.0.5",
   "description": "A module to compile SASS on-the-fly and/or save it to CSS files",
   "main": "dist/index.js",
   "typings": "dist/index.d.ts",
```
