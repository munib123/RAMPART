# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in json
**Pair ID:** 1693_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1693_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```json
Lines 1-31 of the vulnerable file.

{
  "name": "geddy",
  "description": "Web framework for Node.js",
  "keywords": [
    "Web",
    "framework",
    "REST",
    "MVC",
    "realtime"
  ],
  "version": "13.0.7",
  "author": "Matthew Eernisse <mde@fleegix.org> (http://fleegix.org)",
  "dependencies": {
    "barista": "0.2.x",
    "chalk": "^0.4.0",
    "jake": "8.0.x",
    "mime": "1.2.x",
    "model": "6.0.x",
    "tlsopts": "0.0.1",
    "utilities": "1.0.x"
  },
  "bin": {
    "geddy": "./bin/cli.js"
  },
  "scripts": {
    "test": "jake test --trace"
  },
  "main": "./lib/geddy",
  "repository": {
    "type": "git",
    "url": "git://github.com/geddy/geddy.git"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,7 +8,7 @@
     "MVC",
     "realtime"
   ],
-  "version": "13.0.7",
+  "version": "13.0.8",
   "author": "Matthew Eernisse <mde@fleegix.org> (http://fleegix.org)",
   "dependencies": {
     "barista": "0.2.x",
```
