# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in yaml
**Pair ID:** 1891_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** yaml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1891_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```yaml
Lines 1-33 of the vulnerable file.

openapi: 3.0.0
info:
  description: |
    Default API for Flask-Security.

    __N.B. This is preliminary.__

    Since Flask-Security is middleware, with many possible configurations this is a
    guide to how the APIs will behave using standard defaults.

    By default, all POST requests require a CSRF token. This is handled automatically
    if you render the form from your Flask application. If you send JSON, then you must include a request header (configured via __SECURITY_CSRF_HEADER__).
    Please read the online documentation to find out details on how CSRF can be confifgured.

    _Be aware that the current renderer is great! but has some limitations._
    In particular
    it can't represent both form input and JSON input - but all APIs take both.

    You can download the latest spec from: https://github.com/Flask-Middleware/flask-security/blob/master/docs/openapi.yaml
  version: 1.0.0
  title: "Flask-Security External API"
  contact:
    name: Flask-Security-Too
    url: https://github.com/Flask-Middleware/flask-security
  license:
    name: MIT
    url: https://github.com/Flask-Middleware/flask-security/blob/master/LICENSE
paths:
  /login:
    get:
      summary: Retrieve login form and/or user information
      parameters:
        - $ref: "#/components/parameters/include_auth_token"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,7 +10,7 @@
 
     By default, all POST requests require a CSRF token. This is handled automatically
     if you render the form from your Flask application. If you send JSON, then you must include a request header (configured via __SECURITY_CSRF_HEADER__).
-    Please read the online documentation to find out details on how CSRF can be confifgured.
+    Please read the online documentation to find out details on how CSRF can be configured.
 
     _Be aware that the current renderer is great! but has some limitations._
     In particular
@@ -29,8 +29,6 @@
   /login:
     get:
       summary: Retrieve login form and/or user information
-      parameters:
-        - $ref: "#/components/parameters/include_auth_token"
       responses:
         200:
           description: >
```
