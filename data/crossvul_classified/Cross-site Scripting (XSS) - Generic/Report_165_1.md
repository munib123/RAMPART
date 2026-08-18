# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 165_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `165_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "oauth2orize-fprm",
  "version": "0.2.0",
  "description": "Form Post response mode support for OAuth2orize.",
  "keywords": [
    "oauth2",
    "form_post"
  ],
  "author": {
    "name": "Jared Hanson",
    "email": "jaredhanson@gmail.com",
    "url": "http://www.jaredhanson.net/"
  },
  "repository": {
    "type": "git",
    "url": "git://github.com/jaredhanson/oauth2orize-fprm.git"
  },
  "bugs": {
    "url": "http://github.com/jaredhanson/oauth2orize-fprm/issues"
  },
  "license": "MIT",
  "licenses": [
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "oauth2orize-fprm",
-  "version": "0.2.0",
+  "version": "0.2.1",
   "description": "Form Post response mode support for OAuth2orize.",
   "keywords": [
     "oauth2",
```
