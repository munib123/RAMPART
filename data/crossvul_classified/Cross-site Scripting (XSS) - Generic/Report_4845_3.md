# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 4845_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4845_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 1-25 of the vulnerable file.

{
    "type": "extension",
    "id": "com.fastspot.form-builder",
    "version": "1.1",
    "revision": 21,
    "compatibility": "4.2+",
    "title": "Form Builder",
    "description": "An easy to use form builder allowing the administrative users to easily add fields to a form that stores entries in the database and sends out emails. Also supports paid forms.",
    "keywords": [
        "forms",
        "emails",
        "submissions",
        "form"
    ],
    "author": {
        "name": "Tim Buckingham",
        "url": "http://www.fastspot.com",
        "email": "tim@fastspot.com"
    },
    "licenses": {
        "LGPL v3": "http://opensource.org/licenses/LGPL-3.0"
    },
    "components": {
        "module_groups": [],
        "modules": [
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,8 +1,8 @@
 {
     "type": "extension",
     "id": "com.fastspot.form-builder",
-    "version": "1.1",
-    "revision": 21,
+    "version": "1.2",
+    "revision": 22,
     "compatibility": "4.2+",
     "title": "Form Builder",
     "description": "An easy to use form builder allowing the administrative users to easily add fields to a form that stores entries in the database and sends out emails. Also supports paid forms.",
@@ -74,7 +74,7 @@
                         "view": null,
                         "report": null,
                         "class": "server",
-                        "level": "0",
+                        "level": "2",
                         "position": "1"
                     }
                 ],
```
