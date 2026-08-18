# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 954_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `954_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 1-26 of the vulnerable file.

{
  "name": "@nuxt/core",
  "version": "2.6.1",
  "repository": "nuxt/nuxt.js",
  "license": "MIT",
  "files": [
    "dist"
  ],
  "main": "dist/core.js",
  "dependencies": {
    "@nuxt/config": "2.6.1",
    "@nuxt/devalue": "^1.2.2",
    "@nuxt/server": "2.6.1",
    "@nuxt/utils": "2.6.1",
    "@nuxt/vue-renderer": "2.6.1",
    "consola": "^2.6.0",
    "debug": "^4.1.1",
    "esm": "3.2.20",
    "fs-extra": "^7.0.1",
    "hash-sum": "^1.0.2",
    "std-env": "^2.2.1"
  },
  "publishConfig": {
    "access": "public"
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,7 +9,7 @@
   "main": "dist/core.js",
   "dependencies": {
     "@nuxt/config": "2.6.1",
-    "@nuxt/devalue": "^1.2.2",
+    "@nuxt/devalue": "^1.2.3",
     "@nuxt/server": "2.6.1",
     "@nuxt/utils": "2.6.1",
     "@nuxt/vue-renderer": "2.6.1",
```
