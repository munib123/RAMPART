# CrossVul Fix Pair: Improper Authentication in json
**Pair ID:** 2895_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2895_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```json
Lines 1-24 of the vulnerable file.

{
  "name": "nes",
  "description": "WebSocket adapter plugin for hapi routes",
  "version": "6.4.0",
  "repository": "git://github.com/hapijs/nes",
  "main": "lib/index.js",
  "browser": "dist/client.js",
  "keywords": [
    "hapi",
    "plugin",
    "websocket"
  ],
  "engines": {
    "node": ">=4.5.0"
  },
  "dependencies": {
    "boom": "4.x.x",
    "call": "3.x.x",
    "cryptiles": "3.x.x",
    "hoek": "4.x.x",
    "iron": "4.x.x",
    "items": "^2.1.x",
    "joi": "10.x.x",
    "ws": "1.x.x"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 {
   "name": "nes",
   "description": "WebSocket adapter plugin for hapi routes",
-  "version": "6.4.0",
+  "version": "6.4.1",
   "repository": "git://github.com/hapijs/nes",
   "main": "lib/index.js",
   "browser": "dist/client.js",
@@ -31,7 +31,7 @@
     "babel-preset-es2015": "^6.1.2",
     "code": "4.x.x",
     "hapi": "16.x.x",
-    "lab": "11.x.x"
+    "lab": "13.x.x"
   },
   "babel": {
     "presets": ["es2015"]
```
