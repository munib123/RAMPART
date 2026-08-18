# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 954_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `954_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "@nuxt/vue-renderer",
  "version": "2.6.1",
  "repository": "nuxt/nuxt.js",
  "license": "MIT",
  "files": [
    "dist"
  ],
  "main": "dist/vue-renderer.js",
  "dependencies": {
    "@nuxt/devalue": "^1.2.2",
    "@nuxt/utils": "2.6.1",
    "consola": "^2.6.0",
    "fs-extra": "^7.0.1",
    "lru-cache": "^5.1.1",
    "vue": "^2.6.10",
    "vue-meta": "^1.6.0",
    "vue-server-renderer": "^2.6.10"
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
   "main": "dist/vue-renderer.js",
   "dependencies": {
-    "@nuxt/devalue": "^1.2.2",
+    "@nuxt/devalue": "^1.2.3",
     "@nuxt/utils": "2.6.1",
     "consola": "^2.6.0",
     "fs-extra": "^7.0.1",
```
