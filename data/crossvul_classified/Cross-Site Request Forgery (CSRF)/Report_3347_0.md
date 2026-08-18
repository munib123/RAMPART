# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in json
**Pair ID:** 3347_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3347_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```json
Lines 1-6 of the vulnerable file.

{
    "require": {
        "robthree/twofactorauth": "^1.6",
        "yubico/u2flib-server": "^1.0"
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,7 @@
 {
     "require": {
         "robthree/twofactorauth": "^1.6",
-        "yubico/u2flib-server": "^1.0"
+        "yubico/u2flib-server": "^1.0",
+        "owasp/csrf-protector-php": "dev-master"
     }
 }
```
