# CrossVul Fix Pair: Improper Input Validation in json
**Pair ID:** 4630_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4630_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "bmoor",
  "version": "0.8.11",
  "author": "Brian Heilman <das.ist.junk@gmail.com>",
  "description": "A basic foundation for other libraries, establishing useful patterbs, and letting them be more.",
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "git://github.com/b-heilman/bmoor.git"
  },
  "main": "src/index.js",
  "scripts": {
    "demo": "gulp serve",
    "build": "gulp build"
  },
  "dependencies": {
    "uuid": "^3.4.0"
  },
  "devDependencies": {
    "chai": "^4.2.0",
    "gulp": "^4.0.2",
    "gulp-jshint": "^2.1.0",
    "gulp-mocha": "^7.0.2",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "bmoor",
-  "version": "0.8.11",
+  "version": "0.8.12",
   "author": "Brian Heilman <das.ist.junk@gmail.com>",
   "description": "A basic foundation for other libraries, establishing useful patterbs, and letting them be more.",
   "license": "MIT",
```
