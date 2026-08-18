# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1544_7
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1544_7`)

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
$TAB = 'USER';

include($_SERVER['DOCUMENT_ROOT']."/inc/main.php");

// Check user
if ($_SESSION['user'] != 'admin') {
    header("Location: /list/user");
    exit;
}

// Check POST request
if (!empty($_POST['ok'])) {

    // Check empty fields
    if (empty($_POST['v_username'])) $errors[] = __('user');
    if (empty($_POST['v_password'])) $errors[] = __('password');
    if (empty($_POST['v_package'])) $errrors[] = __('package');
    if (empty($_POST['v_email'])) $errors[] = __('email');
    if (empty($_POST['v_fname'])) $errors[] = __('first name');
    if (empty($_POST['v_lname'])) $errors[] = __('last name');
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

    // Validate email
    if ((empty($_SESSION['error_msg'])) && (!filter_var($_POST['v_email'], FILTER_VALIDATE_EMAIL))) {
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
     if (empty($_POST['v_username'])) $errors[] = __('user');
@@ -93,8 +99,8 @@
 
     // Flush field values on success
     if (empty($_SESSION['error_msg'])) {
-        $_SESSION['ok_msg'] = __('USER_CREATED_OK',$_POST['v_username'],$_POST['v_username']);
-        $_SESSION['ok_msg'] .= " / <a href=/login/?loginas=".$_POST['v_username'].">" . __('login as') ." ".$_POST['v_username']. "</a>";
+        $_SESSION['ok_msg'] = __('USER_CREATED_OK',htmlentities($_POST['v_username']),htmlentities($_POST['v_username']));
+        $_SESSION['ok_msg'] .= " / <a href=/login/?loginas=".htmlentities($_POST['v_username']).">" . __('login as') ." ".htmlentities($_POST['v_username']). "</a>";
         unset($v_username);
         unset($v_password);
         unset($v_email);
```
