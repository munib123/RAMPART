# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1440_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1440_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-22 of the vulnerable file.

<?php

// Init
//error_reporting(NULL);


include($_SERVER['DOCUMENT_ROOT']."/inc/main.php");
include($_SERVER['DOCUMENT_ROOT']."/file_manager/fm_core.php");


// todo: set in session?
if (empty($panel)) {
    $command = VESTA_CMD."v-list-user '".$user."' 'json'";
    exec ($command, $output, $return_var);
    if ( $return_var > 0 ) {
        header("Location: /error/");
        exit;
    }
    $panel = json_decode(implode('', $output), true);
}

$fm = new FileManager($user);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,8 +1,8 @@
 <?php
-
 // Init
 //error_reporting(NULL);
 
+header('Content-Type: application/json');
 
 include($_SERVER['DOCUMENT_ROOT']."/inc/main.php");
 include($_SERVER['DOCUMENT_ROOT']."/file_manager/fm_core.php");
```
