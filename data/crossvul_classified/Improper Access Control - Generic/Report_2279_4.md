# CrossVul Fix Pair: Improper Access Control in json
**Pair ID:** 2279_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2279_4`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```json
Lines 1-24 of the vulnerable file.

{
  "name": "crumb",
  "description": "CSRF crumb generation and validation plugin",
  "version": "2.2.0",
  "author": "Eran Hammer <eran@hueniverse.com> (http://hueniverse.com)",
  "contributors": [
    "Marcus Stong <stongo@gmail.com>",
    "Nathan LaFreniere <quitlahok@gmail.com>"
  ],
  "repository": "git://github.com/spumko/crumb",
  "bugs": {
    "url": "https://github.com/spumko/crumb/issues"
  },
  "main": "index",
  "keywords": [
    "hapi",
    "plugin",
    "cookies",
    "csrf",
    "session"
  ],
  "engines": {
    "node": ">=0.10.22"
  },
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 {
   "name": "crumb",
   "description": "CSRF crumb generation and validation plugin",
-  "version": "2.2.0",
+  "version": "3.0.0",
   "author": "Eran Hammer <eran@hueniverse.com> (http://hueniverse.com)",
   "contributors": [
     "Marcus Stong <stongo@gmail.com>",
@@ -30,7 +30,7 @@
     "hapi": ">=2.x.x"
   },
   "devDependencies": {
-    "hapi": "5.x.x",
+    "hapi": "6.x.x",
     "handlebars": "1.3.x",
     "lab": "3.x.x"
   },
```
