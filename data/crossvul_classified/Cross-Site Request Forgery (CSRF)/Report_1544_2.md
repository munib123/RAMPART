# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1544_2
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1544_2`)

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
$TAB = 'DNS';

include($_SERVER['DOCUMENT_ROOT']."/inc/main.php");

// Check POST request for dns domain
if (!empty($_POST['ok'])) {

    // Check empty fields
    if (empty($_POST['v_domain'])) $errors[] = __('domain');
    if (empty($_POST['v_ip'])) $errors[] = __('ip');
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
    $v_domain = preg_replace("/^www./i", "", $_POST['v_domain']);
    $v_domain = escapeshellarg($v_domain);
    $v_domain = strtolower($v_domain);
    $v_ip = escapeshellarg($_POST['v_ip']);
    if (!empty($_POST['v_ns1'])) $v_ns1 = escapeshellarg($_POST['v_ns1']);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,12 @@
 
 // Check POST request for dns domain
 if (!empty($_POST['ok'])) {
+
+    // Check token
+    if ((!isset($_POST['token'])) || ($_SESSION['token'] != $_POST['token'])) {
+        header('location: /login/');
+        exit();
+    }
 
     // Check empty fields
     if (empty($_POST['v_domain'])) $errors[] = __('domain');
@@ -70,7 +76,7 @@
 
     // Flush field values on success
     if (empty($_SESSION['error_msg'])) {
-        $_SESSION['ok_msg'] = __('DNS_DOMAIN_CREATED_OK',$_POST[v_domain],$_POST[v_domain]);
+        $_SESSION['ok_msg'] = __('DNS_DOMAIN_CREATED_OK',htmlentities($_POST[v_domain]),htmlentities($_POST[v_domain]));
         unset($v_domain);
     }
 }
@@ -78,6 +84,12 @@
 
 // Check POST request for dns record
 if (!empty($_POST['ok_rec'])) {
+
+    // Check token
+    if ((!isset($_POST['token'])) || ($_SESSION['token'] != $_POST['token'])) {
+        header('location: /login/');
+        exit();
+    }
 
     // Check empty fields
     if (empty($_POST['v_domain'])) $errors[] = 'domain';
@@ -112,7 +124,7 @@
 
     // Flush field values on success
     if (empty($_SESSION['error_msg'])) {
-        $_SESSION['ok_msg'] = __('DNS_RECORD_CREATED_OK',$_POST[v_rec],$_POST[v_domain]);
+        $_SESSION['ok_msg'] = __('DNS_RECORD_CREATED_OK',htmlentities($_POST[v_rec]),htmlentities($_POST[v_domain]));
         unset($v_domain);
         unset($v_rec);
         unset($v_val);
```
