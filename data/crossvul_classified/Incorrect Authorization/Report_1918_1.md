# CrossVul Fix Pair: Incorrect Authorization in json
**Pair ID:** 1918_1
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1918_1`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```json
Lines 1-37 of the vulnerable file.

{
    "name": "cydrobolt/polr",
    "description": "The Polr URL Shortener.",
    "keywords": ["url-shortener", "url", "cms"],
    "license": "GPLv2+",
    "type": "project",
    "require": {
        "php": ">=5.5.9",
        "laravel/lumen-framework": "5.1.*",
        "vlucas/phpdotenv": "~1.0",
        "illuminate/mail": "~5.1",
        "yajra/laravel-datatables-oracle": "~6.0",
        "paragonie/random_compat": "^1.0.6",
        "torann/geoip": "^1.0",
        "geoip2/geoip2": "^2.4",
        "nesbot/carbon": "^1.22",
        "doctrine/dbal": "^2.5",
        "google/recaptcha": "~1.1",
        "symfony/http-foundation": "2.7.51"
    },
    "require-dev": {
        "fzaninotto/faker": "~1.0",
        "phpunit/phpunit": "^5.2",
        "symfony/css-selector": "^3.0"
    },
    "autoload": {
        "psr-4": {
            "App\\": "app/"
        },
        "classmap": [
            "database/"
        ]
    },
    "autoload-dev": {
        "classmap": [
            "tests/"
        ]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,7 +14,7 @@
         "torann/geoip": "^1.0",
         "geoip2/geoip2": "^2.4",
         "nesbot/carbon": "^1.22",
-        "doctrine/dbal": "^2.5",
+        "doctrine/dbal": "2.5.11",
         "google/recaptcha": "~1.1",
         "symfony/http-foundation": "2.7.51"
     },
```
