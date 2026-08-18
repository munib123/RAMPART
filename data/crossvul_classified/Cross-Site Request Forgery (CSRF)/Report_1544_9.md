# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1544_9
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1544_9`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-23 of the vulnerable file.

<?php
// Init
error_reporting(NULL);
ob_start();
session_start();

include($_SERVER['DOCUMENT_ROOT']."/inc/main.php");

$backup = $_POST['backup'];
$action = $_POST['action'];

switch ($action) {
    case 'delete': $cmd='v-delete-user-backup';
        break;
    default: header("Location: /list/backup/"); exit;
}

foreach ($backup as $value) {
    $value = escapeshellarg($value);
    exec (VESTA_CMD.$cmd." ".$user." ".$value, $output, $return_var);
}

header("Location: /list/backup/");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,6 +8,12 @@
 
 $backup = $_POST['backup'];
 $action = $_POST['action'];
+
+// Check token
+if ((!isset($_POST['token'])) || ($_SESSION['token'] != $_POST['token'])) {
+    header('location: /login/');
+    exit();
+}
 
 switch ($action) {
     case 'delete': $cmd='v-delete-user-backup';
```
