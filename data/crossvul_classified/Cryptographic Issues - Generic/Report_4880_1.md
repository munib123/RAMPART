# CrossVul Fix Pair: Cryptographic Issues in json
**Pair ID:** 4880_1
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4880_1`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```json
Lines 1-26 of the vulnerable file.

{
  "name": "ibm_db",
  "description": "IBM DB2 and IBM Informix bindings for node",
  "version": "1.0.2",
  "main": "lib/odbc.js",
  "homepage": "http://github.com/ibmdb/node-ibm_db/",
  "repository": {
    "type": "git",
    "url": "git://github.com/ibmdb/node-ibm_db.git"
  },
  "bugs": {
    "url": "https://github.com/ibmdb/node-ibm_db/issues"
  },
  "contributors": [
    "IBM <opendev@us.ibm.com>"
  ],
  "directories": {
    "example": "examples",
    "test": "test"
  },
  "engines": {
    "node": ">=0.10.0"
  },
  "scripts": {
    "install": "node installer/driverInstall.js",
    "test": "cd test && node run-tests.js"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,7 +3,7 @@
   "description": "IBM DB2 and IBM Informix bindings for node",
   "version": "1.0.2",
   "main": "lib/odbc.js",
-  "homepage": "http://github.com/ibmdb/node-ibm_db/",
+  "homepage": "https://github.com/ibmdb/node-ibm_db/",
   "repository": {
     "type": "git",
     "url": "git://github.com/ibmdb/node-ibm_db.git"
```
