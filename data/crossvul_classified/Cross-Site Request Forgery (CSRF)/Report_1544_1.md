# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1544_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1544_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-31 of the vulnerable file.

<?php
// Init
error_reporting(NULL);
ob_start();
session_start();
$TAB = 'DB';
include($_SERVER['DOCUMENT_ROOT']."/inc/main.php");

// Check POST request
if (!empty($_POST['ok'])) {

    // Check empty fields
    if (empty($_POST['v_database'])) $errors[] = __('database');
    if (empty($_POST['v_dbuser'])) $errors[] = __('username');
    if (empty($_POST['v_password'])) $errors[] = __('password');
    if (empty($_POST['v_type'])) $errors[] = __('type');
    if (empty($_POST['v_host'])) $errors[] = __('host');
    if (empty($_POST['v_charset'])) $errors[] = __('charset');
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
    if ((!empty($_POST['v_db_email'])) && (empty($_SESSION['error_msg']))) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,6 +8,12 @@
 
 // Check POST request
 if (!empty($_POST['ok'])) {
+
+    // Check token
+    if ((!isset($_POST['token'])) || ($_SESSION['token'] != $_POST['token'])) {
+        header('location: /login/');
+        exit();
+    }
 
     // Check empty fields
     if (empty($_POST['v_database'])) $errors[] = __('database');
@@ -91,7 +97,7 @@
 
     // Flush field values on success
     if (empty($_SESSION['error_msg'])) {
-        $_SESSION['ok_msg'] = __('DATABASE_CREATED_OK',$user."_".$_POST['v_database'],$user."_".$_POST['v_database']);
+        $_SESSION['ok_msg'] = __('DATABASE_CREATED_OK',htmlentities($user)."_".htmlentities($_POST['v_database']),htmlentities($user)."_".htmlentities($_POST['v_database']));
         $_SESSION['ok_msg'] .= " / <a href=".$db_admin_link." target='_blank'>" . __('open %s',$db_admin) . "</a>";
         unset($v_database);
         unset($v_dbuser);
```
