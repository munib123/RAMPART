# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 954_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `954_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 3-43 of the vulnerable file.

  "version": "2.6.1",
  "repository": "nuxt/nuxt.js",
  "license": "MIT",
  "files": [
    "dist"
  ],
  "main": "dist/webpack.js",
  "dependencies": {
    "@babel/core": "^7.4.3",
    "@nuxt/babel-preset-app": "2.6.1",
    "@nuxt/friendly-errors-webpack-plugin": "^2.4.0",
    "@nuxt/utils": "2.6.1",
    "babel-loader": "^8.0.5",
    "cache-loader": "^2.0.1",
    "caniuse-lite": "^1.0.30000957",
    "chalk": "^2.4.2",
    "consola": "^2.6.0",
    "css-loader": "^2.1.1",
    "cssnano": "^4.1.10",
    "eventsource-polyfill": "^0.9.6",
    "extract-css-chunks-webpack-plugin": "^4.3.0",
    "file-loader": "^3.0.1",
    "fs-extra": "^7.0.1",
    "glob": "^7.1.3",
    "hard-source-webpack-plugin": "^0.13.1",
    "hash-sum": "^1.0.2",
    "html-webpack-plugin": "^3.2.0",
    "memory-fs": "^0.4.1",
    "optimize-css-assets-webpack-plugin": "^5.0.1",
    "pify": "^4.0.1",
    "postcss": "^7.0.14",
    "postcss-import": "^12.0.1",
    "postcss-import-resolver": "^1.2.2",
    "postcss-loader": "^3.0.0",
    "postcss-preset-env": "^6.6.0",
    "postcss-url": "^8.0.0",
    "std-env": "^2.2.1",
    "style-resources-loader": "^1.2.1",
    "terser-webpack-plugin": "^1.2.3",
    "thread-loader": "^1.2.0",
    "time-fix-plugin": "^2.0.5",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,7 +20,7 @@
     "css-loader": "^2.1.1",
     "cssnano": "^4.1.10",
     "eventsource-polyfill": "^0.9.6",
-    "extract-css-chunks-webpack-plugin": "^4.3.0",
+    "extract-css-chunks-webpack-plugin": "^4.3.1",
     "file-loader": "^3.0.1",
     "fs-extra": "^7.0.1",
     "glob": "^7.1.3",
```
