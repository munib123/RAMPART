# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1544_8
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1544_8`)

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
$TAB = 'WEB';

include($_SERVER['DOCUMENT_ROOT']."/inc/main.php");

// Check POST request
if (!empty($_POST['ok'])) {

    // Check for empty fields
    if (empty($_POST['v_domain'])) $errors[] = __('domain');
    if (empty($_POST['v_ip'])) $errors[] = __('ip');
    if ((!empty($_POST['v_ssl'])) && (empty($_POST['v_ssl_crt']))) $errors[] = __('ssl certificate');
    if ((!empty($_POST['v_ssl'])) && (empty($_POST['v_ssl_key']))) $errors[] = __('ssl key');
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

    // Check stats password length
    if ((!empty($v_stats)) && (empty($_SESSION['error_msg']))) {
        if (!empty($_POST['v_stats_user'])) {
            $pw_len = strlen($_POST['v_stats_password']);
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
 
     // Check for empty fields
     if (empty($_POST['v_domain'])) $errors[] = __('domain');
@@ -314,7 +320,7 @@
         }
 
         if (!empty($_SESSION['error_msg']) && $domain_added) {
-            $_SESSION['ok_msg'] = __('WEB_DOMAIN_CREATED_OK',$_POST[v_domain],$_POST[v_domain]);
+            $_SESSION['ok_msg'] = __('WEB_DOMAIN_CREATED_OK',htmlentities($_POST[v_domain]),htmlentities($_POST[v_domain]));
             $_SESSION['flash_error_msg'] = $_SESSION['error_msg'];
             $url = '/edit/web/?domain='.strtolower(preg_replace("/^www\./i", "", $_POST['v_domain']));
             header('Location: ' . $url);
@@ -324,7 +330,7 @@
 
     // Flush field values on success
     if (empty($_SESSION['error_msg'])) {
-        $_SESSION['ok_msg'] = __('WEB_DOMAIN_CREATED_OK',$_POST[v_domain],$_POST[v_domain]);
+        $_SESSION['ok_msg'] = __('WEB_DOMAIN_CREATED_OK',htmlentities($_POST[v_domain]),htmlentities($_POST[v_domain]));
         unset($v_domain);
         unset($v_aliases);
         unset($v_ssl);
```
