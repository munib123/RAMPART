# CrossVul Fix Pair: Improper Input Validation in json
**Pair ID:** 4625_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4625_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
	"name": "@irrelon/path",
	"version": "4.6.8",
	"description": "A powerful JSON path processor. Allows you to drill into and manipulate JSON objects with a simple dot-delimited path format e.g. \"obj.name\".",
	"main": "./src/Path.js",
	"scripts": {
		"test": "NODE_ENV=test mocha ./tests/**/**.test.js",
		"testMon": "nodemon --watch src --watch tests --exec \"NODE_ENV=test BABEL_DISABLE_CACHE=1 mocha ./tests/**/**.test.js\"",
		"build": "npm test && rimraf dist && babel ./src/*.js --out-dir dist",
		"eslint": "eslint ./src/**.js ./tests/**.js ./dist/Path.js",
		"eslint-fix": "eslint --fix ./src/**.js ./tests/**.js"
	},
	"keywords": [
		"path",
		"dot notation",
		"json",
		"node",
		"browser"
	],
	"author": "Rob Evans - Irrelon Software Limited",
	"license": "MIT",
	"devDependencies": {
		"@babel/cli": "^7.8.7",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
 	"name": "@irrelon/path",
-	"version": "4.6.8",
+	"version": "4.7.0",
 	"description": "A powerful JSON path processor. Allows you to drill into and manipulate JSON objects with a simple dot-delimited path format e.g. \"obj.name\".",
 	"main": "./src/Path.js",
 	"scripts": {
```
