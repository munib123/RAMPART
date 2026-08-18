# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in json
**Pair ID:** 531_1
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `531_1`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```json
Lines 1-26 of the vulnerable file.

{
  "author": "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me/)",
  "name": "tar",
  "description": "tar for node",
  "version": "2.2.1",
  "repository": {
    "type": "git",
    "url": "git://github.com/isaacs/node-tar.git"
  },
  "main": "tar.js",
  "scripts": {
    "test": "tap test/*.js"
  },
  "dependencies": {
    "block-stream": "*",
    "fstream": "^1.0.2",
    "inherits": "2"
  },
  "devDependencies": {
    "graceful-fs": "^4.1.2",
    "rimraf": "1.x",
    "tap": "0.x",
    "mkdirp": "^0.5.0"
  },
  "license": "ISC"
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,7 +13,7 @@
   },
   "dependencies": {
     "block-stream": "*",
-    "fstream": "^1.0.2",
+    "fstream": "^1.0.12",
     "inherits": "2"
   },
   "devDependencies": {
```
