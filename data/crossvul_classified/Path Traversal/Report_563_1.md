# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in json
**Pair ID:** 563_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `563_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "crud-file-server",
  "version": "0.8.0",
  "description": "file server supporting basic create, read, update, & delete for any kind of file",
  "bin": {
    "crud-file-server": "./bin/crud-file-server"
  },
  "main": "./crud-file-server.js",
  "repository": {
    "type": "git",
    "url": "https://github.com/omphalos/crud-file-server.git"
  },
  "keywords": [
    "static",
    "file",
    "fs",
    "http"
  ],
  "dependencies": {
    "optimist": "0.3.4",
	"mime": "1.2.7"
  },
  "license": "unlicense",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "crud-file-server",
-  "version": "0.8.0",
+  "version": "0.9.0",
   "description": "file server supporting basic create, read, update, & delete for any kind of file",
   "bin": {
     "crud-file-server": "./bin/crud-file-server"
```
