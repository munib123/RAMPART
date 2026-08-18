# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in json
**Pair ID:** 4195_8
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4195_8`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "ad-ldap-connector",
  "version": "5.0.12",
  "description": "ADLDAP Federation Connector",
  "main": "server.js",
  "scripts": {
    "test": "NODE_TLS_REJECT_UNAUTHORIZED=0 mocha --timeout 50000 --reporter spec --exit",
    "snyk": "snyk test",
    "start": "node server.js"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/auth0/ad-ldap-connector.git"
  },
  "keywords": [
    "sql",
    "federation",
    "identity",
    "ws-federation"
  ],
  "author": "Auth0",
  "license": "MIT",
  "dependencies": {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "ad-ldap-connector",
-  "version": "5.0.12",
+  "version": "5.0.13",
   "description": "ADLDAP Federation Connector",
   "main": "server.js",
   "scripts": {
@@ -32,6 +32,7 @@
     "connect-multiparty": "^2.2.0",
     "cookie-parser": "^1.4.3",
     "cookie-sessions": "github:auth0/cookie-sessions#53a8aae",
+    "csurf": "1.9.0",
     "ejs": "^2.5.5",
     "express": "^4.16.4",
     "express-passport-logout": "~0.1.0",
```
