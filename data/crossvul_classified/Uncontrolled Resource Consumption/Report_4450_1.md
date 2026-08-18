# CrossVul Fix Pair: Uncontrolled Resource Consumption in json
**Pair ID:** 4450_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4450_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "multi-ini",
  "version": "2.1.1",
  "license": "MIT",
  "description": "An ini-file parser which supports multi line, multiple levels and arrays to get a maximum of compatibility with Zend config files.",
  "main": "lib/index.js",
  "scripts": {
    "predistribute": "babel src --out-dir lib",
    "test": "babel-node ./node_modules/.bin/_mocha",
    "coverage": "babel-node ./node_modules/.bin/istanbul cover _mocha",
    "distribute": "npm publish"
  },
  "homepage": "https://github.com/evangelion1204/multi-ini",
  "author": {
    "name": "Michael Iwersen",
    "email": "mi.iwersen@gmail.com"
  },
  "repository": {
    "type": "git",
    "url": "git://github.com/evangelion1204/multi-ini.git"
  },
  "bugs": {
    "url": "https://github.com/evangelion1204/multi-ini/issues"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "multi-ini",
-  "version": "2.1.1",
+  "version": "2.1.2",
   "license": "MIT",
   "description": "An ini-file parser which supports multi line, multiple levels and arrays to get a maximum of compatibility with Zend config files.",
   "main": "lib/index.js",
```
