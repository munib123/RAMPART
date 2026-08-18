# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in json
**Pair ID:** 3901_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3901_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "@actions/http-client",
  "version": "1.0.7",
  "description": "Actions Http Client",
  "main": "index.js",
  "scripts": {
    "build": "rm -Rf ./_out && tsc && cp package*.json ./_out && cp *.md ./_out && cp LICENSE ./_out && cp actions.png ./_out",
    "test": "jest",
    "format": "prettier --write *.ts && prettier --write **/*.ts",
    "format-check": "prettier --check *.ts && prettier --check **/*.ts",
    "audit-check": "npm audit --audit-level=moderate"
  },
  "repository": {
    "type": "git",
    "url": "git+https://github.com/actions/http-client.git"
  },
  "keywords": [
    "Actions",
    "Http"
  ],
  "author": "GitHub, Inc.",
  "license": "MIT",
  "bugs": {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "@actions/http-client",
-  "version": "1.0.7",
+  "version": "1.0.8",
   "description": "Actions Http Client",
   "main": "index.js",
   "scripts": {
```
