# CrossVul Fix Pair: Incorrect Authorization in json
**Pair ID:** 2465_3
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2465_3`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```json
Lines 1-40 of the vulnerable file.

{
    "name": "symfony/security-http",
    "type": "library",
    "description": "Symfony Security Component - HTTP Integration",
    "keywords": [],
    "homepage": "https://symfony.com",
    "license": "MIT",
    "authors": [
        {
            "name": "Fabien Potencier",
            "email": "fabien@symfony.com"
        },
        {
            "name": "Symfony Community",
            "homepage": "https://symfony.com/contributors"
        }
    ],
    "require": {
        "php": "^7.1.3",
        "symfony/security-core": "^4.4",
        "symfony/http-foundation": "^3.4.40|^4.4.7|^5.0.7",
        "symfony/http-kernel": "^4.4",
        "symfony/property-access": "^3.4|^4.0|^5.0"
    },
    "require-dev": {
        "symfony/routing": "^3.4|^4.0|^5.0",
        "symfony/security-csrf": "^3.4.11|^4.0.11|^5.0",
        "psr/log": "~1.0"
    },
    "conflict": {
        "symfony/event-dispatcher": ">=5",
        "symfony/security-csrf": "<3.4.11|~4.0,<4.0.11"
    },
    "suggest": {
        "symfony/security-csrf": "For using tokens to protect authentication/logout attempts",
        "symfony/routing": "For using the HttpUtils class to create sub-requests, redirect the user, and match URLs"
    },
    "autoload": {
        "psr-4": { "Symfony\\Component\\Security\\Http\\": "" },
        "exclude-from-classmap": [
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,7 +17,7 @@
     ],
     "require": {
         "php": "^7.1.3",
-        "symfony/security-core": "^4.4",
+        "symfony/security-core": "^4.4.7",
         "symfony/http-foundation": "^3.4.40|^4.4.7|^5.0.7",
         "symfony/http-kernel": "^4.4",
         "symfony/property-access": "^3.4|^4.0|^5.0"
```
