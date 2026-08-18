# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1544_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1544_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-32 of the vulnerable file.

<?php
// Init
error_reporting(NULL);
ob_start();
session_start();
$TAB = 'CRON';

include($_SERVER['DOCUMENT_ROOT']."/inc/main.php");

// Check POST request
if (!empty($_POST['ok'])) {

    // Check empty fields
    if ((!isset($_POST['v_min'])) || ($_POST['v_min'] == '')) $errors[] = __('minute');
    if ((!isset($_POST['v_hour'])) || ($_POST['v_hour'] == '')) $errors[] = __('hour');
    if ((!isset($_POST['v_day'])) || ($_POST['v_day'] == '')) $errors[] = __('day');
    if ((!isset($_POST['v_month'])) || ($_POST['v_month'] == '')) $errors[] = __('month');
    if ((!isset($_POST['v_wday'])) || ($_POST['v_wday'] == '')) $errors[] = __('day of week');
    if ((!isset($_POST['v_cmd'])) || ($_POST['v_cmd'] == '')) $errors[] = __('cmd');
    if (!empty($errors[0])) {
        foreach ($errors as $i => $error) {
            if ( $i == 0 ) {
                $error_msg = $error;
            } else {
                $error_msg = $error_msg.", ".$error;
            }
        }
        $_SESSION['error_msg'] = __('Field "%s" can not be blank.',$error_msg);
    }

    // Protect input
    $v_min = escapeshellarg($_POST['v_min']);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,12 @@
 
 // Check POST request
 if (!empty($_POST['ok'])) {
+
+    // Check token
+    if ((!isset($_POST['token'])) || ($_SESSION['token'] != $_POST['token'])) {
+        header('location: /login/');
+        exit();
+    }
 
     // Check empty fields
     if ((!isset($_POST['v_min'])) || ($_POST['v_min'] == '')) $errors[] = __('minute');
```
