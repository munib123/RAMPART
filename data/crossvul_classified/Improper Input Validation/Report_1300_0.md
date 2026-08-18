# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 1300_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1300_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 1-17 of the vulnerable file.

<?php

// Including the check_permission file, don't delete the following row!
require(__DIR__ . '/check_permission.php');

if(isset($_POST["username"]) or isset($_POST["password"])){
    $tmpusername = strip_tags($_POST["username"]);
    $tmpusername = htmlspecialchars($tmpusername, ENT_QUOTES);
    $tmppassword = md5($_POST["password"]);
    $data = '$username = "'.$tmpusername.'"; $password = \''.$tmppassword.'\';'.PHP_EOL;
    $fp = fopen(__DIR__ . '/pluginconfig.php', 'a');
    fwrite($fp, $data);
    unlink(__DIR__ . "/new.php");
    unlink(__DIR__ . "/create.php");
    header("Location: imgbrowser.php");
} 

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,14 +4,14 @@
 require(__DIR__ . '/check_permission.php');
 
 if(isset($_POST["username"]) or isset($_POST["password"])){
-    $tmpusername = strip_tags($_POST["username"]);
-    $tmpusername = htmlspecialchars($tmpusername, ENT_QUOTES);
+    // only allow alphanumeric, underscore, dot, and dash for username
+    $tmpusername =  preg_replace("/[^a-zA-Z0-9_.\-]+/", "", $_POST["username"]);
     $tmppassword = md5($_POST["password"]);
-    $data = '$username = "'.$tmpusername.'"; $password = \''.$tmppassword.'\';'.PHP_EOL;
+    $data = '$username = \''.$tmpusername.'\'; $password = \''.$tmppassword.'\';'.PHP_EOL;
     $fp = fopen(__DIR__ . '/pluginconfig.php', 'a');
     fwrite($fp, $data);
     unlink(__DIR__ . "/new.php");
     unlink(__DIR__ . "/create.php");
     header("Location: imgbrowser.php");
-} 
+}
 
```
