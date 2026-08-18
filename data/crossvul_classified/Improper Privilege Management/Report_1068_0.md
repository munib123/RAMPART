# CrossVul Fix Pair: Improper Privilege Management in php
**Pair ID:** 1068_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1068_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```php
Lines 1-22 of the vulnerable file.

<?php

$installationVersion = "7.5";


header('Content-Type: application/json');

$obj = new stdClass();
$obj->post = $_POST;

if (!file_exists($_POST['systemRootPath'] . "index.php")) {
    $obj->error = "Your system path to application ({$_POST['systemRootPath']}) is wrong";
    echo json_encode($obj);
    exit;
}

$mysqli = @new mysqli($_POST['databaseHost'], $_POST['databaseUser'], $_POST['databasePass'], "", $_POST['databasePort']);

/*
 * This is the "official" OO way to do it,
 * BUT $connect_error was broken until PHP 5.2.9 and 5.3.0.
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,8 @@
 <?php
+if (file_exists("../videos/configuration.php")) {
+    error_log("Can not create configuration again: ".  json_encode($_SERVER));
+    exit;
+}
 
 $installationVersion = "7.5";
 
```
