# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 1587_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1587_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 1-26 of the vulnerable file.

{
  "name": "nodebb-plugin-markdown",
  "version": "1.0.2",
  "description": "A Markdown parser for NodeBB",
  "main": "index.js",
  "repository": {
    "type": "git",
    "url": "https://github.com/julianlam/nodebb-plugin-markdown"
  },
  "keywords": [
    "nodebb",
    "plugin",
    "markdown"
  ],
  "author": "Julian Lam <julian@designcreateplay.com>",
  "license": "MIT",
  "bugs": {
    "url": "https://github.com/julianlam/nodebb-plugin-markdown/issues"
  },
  "dependencies": {
    "remarkable": "^1.3.0"
  },
  "nbbpm": {
    "compatibility": "^0.7.0"
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,7 +18,7 @@
     "url": "https://github.com/julianlam/nodebb-plugin-markdown/issues"
   },
   "dependencies": {
-    "remarkable": "^1.3.0"
+    "markdown-it": "^4.0.3"
   },
   "nbbpm": {
     "compatibility": "^0.7.0"
```
