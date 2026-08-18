# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 4634_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4634_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 5-45 of the vulnerable file.

  "main": "./src/index.js",
  "scripts": {
    "build": "npm run clean && webpack --progress --colors --bail",
    "clean": "rimraf ./dist",
    "start": "webpack-dev-server",
    "test": "npm run test:lint && npm run test:unit",
    "test:lint": "eslint . --ext .js",
    "test:unit": "tap ./test/*.js",
    "watch": "webpack --progress --colors --watch"
  },
  "author": "Massachusetts Institute of Technology",
  "license": "BSD-3-Clause",
  "homepage": "https://github.com/LLK/scratch-svg-renderer#readme",
  "repository": {
    "type": "git",
    "url": "git+ssh://git@github.com/LLK/scratch-svg-renderer.git"
  },
  "dependencies": {
    "base64-js": "1.2.1",
    "base64-loader": "1.0.0",
    "minilog": "3.1.0",
    "transformation-matrix": "1.15.0",
    "scratch-render-fonts": "1.0.0-prerelease.20200507182347"
  },
  "devDependencies": {
    "babel-core": "6.26.0",
    "babel-eslint": "^8.1.2",
    "babel-loader": "7.1.5",
    "babel-preset-env": "1.6.1",
    "copy-webpack-plugin": "^4.5.1",
    "eslint": "^4.14.0",
    "eslint-config-scratch": "^5.0.0",
    "eslint-plugin-import": "^2.12.0",
    "jsdom": "^13.0.0",
    "json": "^9.0.6",
    "lodash.defaultsdeep": "4.6.1",
    "mkdirp": "^1.0.3",
    "rimraf": "^3.0.1",
    "tap": "^11.0.1",
    "webpack": "^4.8.0",
    "webpack-cli": "^3.1.0",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,6 +22,7 @@
   "dependencies": {
     "base64-js": "1.2.1",
     "base64-loader": "1.0.0",
+    "dompurify": "2.1.1",
     "minilog": "3.1.0",
     "transformation-matrix": "1.15.0",
     "scratch-render-fonts": "1.0.0-prerelease.20200507182347"
```
