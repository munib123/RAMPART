# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1544_4
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1544_4`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-38 of the vulnerable file.

<?php
// Init
error_reporting(NULL);
ob_start();
session_start();
$TAB = 'IP';

include($_SERVER['DOCUMENT_ROOT']."/inc/main.php");

// Check user
if ($_SESSION['user'] != 'admin') {
    header("Location: /list/user");
    exit;
}

// Check POST request
if (!empty($_POST['ok'])) {

    // Check empty fields
    if (empty($_POST['v_ip'])) $errors[] = __('ip address');
    if (empty($_POST['v_netmask'])) $errors[] = __('netmask');
    if (empty($_POST['v_interface'])) $errors[] = __('interface');
    if (empty($_POST['v_owner'])) $errors[] = __('assigned user');
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
    $v_ip = escapeshellarg($_POST['v_ip']);
    $v_netmask = escapeshellarg($_POST['v_netmask']);
    $v_name = escapeshellarg($_POST['v_name']);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,6 +15,12 @@
 
 // Check POST request
 if (!empty($_POST['ok'])) {
+
+    // Check token
+    if ((!isset($_POST['token'])) || ($_SESSION['token'] != $_POST['token'])) {
+        header('location: /login/');
+        exit();
+    }
 
     // Check empty fields
     if (empty($_POST['v_ip'])) $errors[] = __('ip address');
@@ -61,7 +67,7 @@
 
     // Flush field values on success
     if (empty($_SESSION['error_msg'])) {
-        $_SESSION['ok_msg'] = __('IP_CREATED_OK',$_POST['v_ip'],$_POST['v_ip']);
+        $_SESSION['ok_msg'] = __('IP_CREATED_OK',htmlentities($_POST['v_ip']),htmlentities($_POST['v_ip']));
         unset($v_ip);
         unset($v_netmask);
         unset($v_name);
```
