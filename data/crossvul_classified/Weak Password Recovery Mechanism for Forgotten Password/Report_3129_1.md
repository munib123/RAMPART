# CrossVul Fix Pair: Weak Password Recovery Mechanism for Forgotten Password in php
**Pair ID:** 3129_1
**Vulnerability Class:** Weak Password Recovery Mechanism for Forgotten Password
**CWE:** CWE-640
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3129_1`)

## Vulnerability Information & PoC

## Description
Weak Password Recovery Mechanism for Forgotten Password - It is common for an application to have a mechanism that provides a means for a user to gain access to their account in the event they forget their password.

## Vulnerable Code
```php
Lines 1-27 of the vulnerable file.

<?php

return [

    'application' => [

        'version' => '1.0.10'

    ],

    'auth' => [

        'table' => '@system_auth',
        'cookie' => [
            'name' => 'pagekit_auth',
            'lifetime' => 315360000
        ]

    ],

    'debug' => [

        'file' => "sqlite:$path/tmp/temp/debug.db"

    ],

    'session' => [
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,7 @@
 
     'application' => [
 
-        'version' => '1.0.10'
+        'version' => '1.0.11'
 
     ],
 
```
