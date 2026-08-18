# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2897_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2897_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 315-350 of the vulnerable file.

    |--------------------------------------------------------------------------
    |
    | If safe mode is enabled, the PHP code section is disabled in the CMS
    | for security reasons. If set to null, safe mode is enabled when
    | debug mode (app.debug) is disabled.
    |
    */

    'enableSafeMode' => null,

    /*
    |--------------------------------------------------------------------------
    | Cross Site Request Forgery (CSRF) Protection
    |--------------------------------------------------------------------------
    |
    | If the CSRF protection is enabled, all "postback" requests are checked
    | for a valid security token.
    |
    */

    'enableCsrfProtection' => false,

    /*
    |--------------------------------------------------------------------------
    | Force bytecode invalidation
    |--------------------------------------------------------------------------
    |
    | When using OPcache with opcache.validate_timestamps set to 0 or APC
    | with apc.stat set to 0 and Twig cache enabled, clearing the template
    | cache won't update the cache, set to true to get around this.
    |
    */

    'forceBytecodeInvalidation' => true,

];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -332,7 +332,7 @@
     |
     */
 
-    'enableCsrfProtection' => false,
+    'enableCsrfProtection' => true,
 
     /*
     |--------------------------------------------------------------------------
```
