# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in json
**Pair ID:** 2049_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2049_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```json
Lines 1-24 of the vulnerable file.

{
  "name": "inert",
  "description": "Static file and directory handlers for hapi.js",
  "version": "1.1.0",
  "repository": "git://github.com/hapijs/inert",
  "main": "index",
  "keywords": [
    "file",
    "directory",
    "handler",
    "hapi"
  ],
  "engines": {
    "node": ">=0.10.32"
  },
  "dependencies": {
    "boom": "2.x.x",
    "hoek": "2.x.x",
    "items": "1.x.x",
    "joi": "^4.7.x",
    "mimos": "1.x.x",
    "lru-cache": "2.5.x"
  },
  "devDependencies": {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 {
   "name": "inert",
   "description": "Static file and directory handlers for hapi.js",
-  "version": "1.1.0",
+  "version": "1.1.1",
   "repository": "git://github.com/hapijs/inert",
   "main": "index",
   "keywords": [
```
