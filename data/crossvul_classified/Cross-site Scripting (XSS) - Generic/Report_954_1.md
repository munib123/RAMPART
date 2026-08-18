# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 954_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `954_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 1-29 of the vulnerable file.

{
  "name": "@nuxt/builder",
  "version": "2.6.1",
  "repository": "nuxt/nuxt.js",
  "license": "MIT",
  "files": [
    "dist"
  ],
  "main": "dist/builder.js",
  "dependencies": {
    "@nuxt/devalue": "^1.2.2",
    "@nuxt/utils": "2.6.1",
    "@nuxt/vue-app": "2.6.1",
    "chokidar": "^2.1.5",
    "consola": "^2.6.0",
    "fs-extra": "^7.0.1",
    "glob": "^7.1.3",
    "hash-sum": "^1.0.2",
    "ignore": "^5.0.6",
    "lodash": "^4.17.11",
    "pify": "^4.0.1",
    "semver": "^6.0.0",
    "serialize-javascript": "^1.6.1",
    "upath": "^1.1.2"
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
@@ -8,7 +8,7 @@
   ],
   "main": "dist/builder.js",
   "dependencies": {
-    "@nuxt/devalue": "^1.2.2",
+    "@nuxt/devalue": "^1.2.3",
     "@nuxt/utils": "2.6.1",
     "@nuxt/vue-app": "2.6.1",
     "chokidar": "^2.1.5",
@@ -16,7 +16,7 @@
     "fs-extra": "^7.0.1",
     "glob": "^7.1.3",
     "hash-sum": "^1.0.2",
-    "ignore": "^5.0.6",
+    "ignore": "^5.1.0",
     "lodash": "^4.17.11",
     "pify": "^4.0.1",
     "semver": "^6.0.0",
```
