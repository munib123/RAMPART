# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1544_6
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1544_6`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-39 of the vulnerable file.

<?php
// Init
error_reporting(NULL);
ob_start();
session_start();
$TAB = 'PACKAGE';

include($_SERVER['DOCUMENT_ROOT']."/inc/main.php");

// Check user
if ($_SESSION['user'] != 'admin') {
    header("Location: /list/user");
    exit;
}

// Check POST request
if (!empty($_POST['ok'])) {

    // Check empty fields
    if (empty($_POST['v_package'])) $errors[] = __('package');
    if (empty($_POST['v_web_template'])) $errors[] = __('web template');
    if (!empty($_SESSION['WEB_SYSTEM'])) {
        if (empty($_POST['v_backend_template'])) $errors[] = __('backend template');
    }
    if (!empty($_SESSION['PROXY_SYSTEM'])) {
        if (empty($_POST['v_proxy_template'])) $errors[] = __('proxy template');
    }
    if (empty($_POST['v_dns_template'])) $errors[] = __('dns template');
    if (empty($_POST['v_shell'])) $errrors[] = __('shell');
    if (!isset($_POST['v_web_domains'])) $errors[] = __('web domains');
    if (!isset($_POST['v_web_aliases'])) $errors[] = __('web aliases');
    if (!isset($_POST['v_dns_domains'])) $errors[] = __('dns domains');
    if (!isset($_POST['v_dns_records'])) $errors[] = __('dns records');
    if (!isset($_POST['v_mail_domains'])) $errors[] = __('mail domains');
    if (!isset($_POST['v_mail_accounts'])) $errors[] = __('mail accounts');
    if (!isset($_POST['v_databases'])) $errors[] = __('databases');
    if (!isset($_POST['v_cron_jobs'])) $errors[] = __('cron jobs');
    if (!isset($_POST['v_backups'])) $errors[] = __('backups');
    if (!isset($_POST['v_disk_quota'])) $errors[] = __('quota');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,10 +16,16 @@
 // Check POST request
 if (!empty($_POST['ok'])) {
 
+    // Check token
+    if ((!isset($_POST['token'])) || ($_SESSION['token'] != $_POST['token'])) {
+        header('location: /login/');
+        exit();
+    }
+
     // Check empty fields
     if (empty($_POST['v_package'])) $errors[] = __('package');
     if (empty($_POST['v_web_template'])) $errors[] = __('web template');
-    if (!empty($_SESSION['WEB_SYSTEM'])) {
+    if (!empty($_SESSION['WEB_BACKEND'])) {
         if (empty($_POST['v_backend_template'])) $errors[] = __('backend template');
     }
     if (!empty($_SESSION['PROXY_SYSTEM'])) {
@@ -132,7 +138,7 @@
 
     // Flush field values on success
     if (empty($_SESSION['error_msg'])) {
-        $_SESSION['ok_msg'] = __('PACKAGE_CREATED_OK',$_POST['v_package'],$_POST['v_package']);
+        $_SESSION['ok_msg'] = __('PACKAGE_CREATED_OK',htmlentities($_POST['v_package']),htmlentities($_POST['v_package']));
         unset($v_package);
     }
 
```
