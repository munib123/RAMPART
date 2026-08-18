# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 3810_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3810_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 1-10 of the vulnerable file.

<?php

list($blank, $uuid, $blank) = split("/", $_SERVER["PATH_INFO"]);
shell_exec("/usr/sbin/oo-restorer-wrapper.sh $uuid");

sleep(2);
$url=str_replace("/$uuid", "", $_SERVER["PATH_INFO"]);
header("Location: $url");

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,10 +1,16 @@
 <?php
 
 list($blank, $uuid, $blank) = split("/", $_SERVER["PATH_INFO"]);
-shell_exec("/usr/sbin/oo-restorer-wrapper.sh $uuid");
-
-sleep(2);
-$url=str_replace("/$uuid", "", $_SERVER["PATH_INFO"]);
-header("Location: $url");
-
+if (preg_match('/[0-9a-fA-F]{32}/', $uuid)) {
+    shell_exec("/usr/sbin/oo-restorer-wrapper.sh $uuid");
+    sleep(2);
+    $host = $_SERVER['HTTP_HOST'];
+    $proto = "http" . ( isset($_SERVER['HTTPS']) ? 's' : '' ) . '://';
+    $url=str_replace("/$uuid", "", $_SERVER["PATH_INFO"]);
+    header("Location: $proto$host$url");
+} else {
+    // someone is trying to attack
+    error_log("Invalid uuid $uuid given to restorer.php");
+    header('HTTP/1.0 403 Forbidden');
+}
 ?>
```
