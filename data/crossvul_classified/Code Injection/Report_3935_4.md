# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in json
**Pair ID:** 3935_4
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3935_4`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "dns-sync",
  "version": "0.2.0",
  "description": "dns-sync",
  "main": "index.js",
  "scripts": {
    "test": "mocha",
    "lint": "eslint ."
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "dns-sync",
-  "version": "0.2.0",
+  "version": "0.2.1",
   "description": "dns-sync",
   "main": "index.js",
   "scripts": {
```
