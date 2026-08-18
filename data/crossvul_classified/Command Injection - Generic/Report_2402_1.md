# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in json
**Pair ID:** 2402_1
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2402_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "dns-sync",
  "version": "0.1.0",
  "description": "dns-sync",
  "main": "index.js",
  "scripts": {
    "test": "make test"
  },
  "homepage": "https://github.com/skoranga/node-dns-sync",
  "repository": {
    "type": "git",
    "url": "git@github.com:skoranga/node-dns-sync.git"
  },
  "keywords": [
    "dns sync",
    "server startup",
    "nodejs"
  ],
  "author": "Sanjeev Koranga",
  "license": "MIT",
  "readmeFilename": "README.md",
  "dependencies": {
    "debug" : "~0.7",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "dns-sync",
-  "version": "0.1.0",
+  "version": "0.1.1",
   "description": "dns-sync",
   "main": "index.js",
   "scripts": {
@@ -20,11 +20,11 @@
   "license": "MIT",
   "readmeFilename": "README.md",
   "dependencies": {
-    "debug" : "~0.7",
-    "shelljs": "~0.2"
+    "debug" : "^2",
+    "shelljs": "~0.3"
   },
   "devDependencies": {
-    "mocha" : "~1",
-    "jshint" : "*"
+    "mocha" : "^1",
+    "jshint" : "^2"
   }
 }
```
