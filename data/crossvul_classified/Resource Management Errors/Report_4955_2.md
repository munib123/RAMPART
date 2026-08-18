# CrossVul Fix Pair: Resource Management Errors in json
**Pair ID:** 4955_2
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4955_2`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```json
Lines 1-24 of the vulnerable file.

{
  "name": "hawk",
  "description": "HTTP Hawk Authentication Scheme",
  "version": "4.1.0",
  "author": "Eran Hammer <eran@hammer.io> (http://hueniverse.com)",
  "repository": "git://github.com/hueniverse/hawk",
  "main": "lib/index.js",
  "browser": "dist/browser.js",
  "keywords": [
    "http",
    "authentication",
    "scheme",
    "hawk"
  ],
  "engines": {
    "node": ">=4.0.0"
  },
  "dependencies": {
    "hoek": "3.x.x",
    "boom": "3.x.x",
    "cryptiles": "3.x.x",
    "sntp": "2.x.x"
  },
  "devDependencies": {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 {
   "name": "hawk",
   "description": "HTTP Hawk Authentication Scheme",
-  "version": "4.1.0",
+  "version": "4.1.1",
   "author": "Eran Hammer <eran@hammer.io> (http://hueniverse.com)",
   "repository": "git://github.com/hueniverse/hawk",
   "main": "lib/index.js",
```
