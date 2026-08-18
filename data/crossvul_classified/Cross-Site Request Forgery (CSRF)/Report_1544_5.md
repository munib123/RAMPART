# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1544_5
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1544_5`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-33 of the vulnerable file.

<?php
// Init
error_reporting(NULL);
ob_start();
session_start();
$TAB = 'MAIL';

include($_SERVER['DOCUMENT_ROOT']."/inc/main.php");


// Check POST request for mail domain
if (!empty($_POST['ok'])) {

    // Check empty fields
    if (empty($_POST['v_domain'])) $errors[] = __('domain');
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

    // Check antispam option
    if (!empty($_POST['v_antispam'])) {
        $v_antispam = 'yes';
    } else {
        $v_antispam = 'no';
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,6 +10,12 @@
 
 // Check POST request for mail domain
 if (!empty($_POST['ok'])) {
+
+    // Check token
+    if ((!isset($_POST['token'])) || ($_SESSION['token'] != $_POST['token'])) {
+        header('location: /login/');
+        exit();
+    }
 
     // Check empty fields
     if (empty($_POST['v_domain'])) $errors[] = __('domain');
@@ -59,7 +65,7 @@
 
     // Flush field values on success
     if (empty($_SESSION['error_msg'])) {
-        $_SESSION['ok_msg'] = __('MAIL_DOMAIN_CREATED_OK',$_POST['v_domain'],$_POST['v_domain']);
+        $_SESSION['ok_msg'] = __('MAIL_DOMAIN_CREATED_OK',htmlentities($_POST['v_domain']),htmlentities($_POST['v_domain']));
         unset($v_domain);
     }
 }
@@ -67,6 +73,12 @@
 
 // Check POST request for mail account
 if (!empty($_POST['ok_acc'])) {
+
+    // Check token
+    if ((!isset($_POST['token'])) || ($_SESSION['token'] != $_POST['token'])) {
+        header('location: /login/');
+        exit();
+    }
 
     // Check empty fields
     if (empty($_POST['v_domain'])) $errors[] = __('domain');
@@ -156,7 +168,7 @@
 
     // Flush field values on success
     if (empty($_SESSION['error_msg'])) {
-        $_SESSION['ok_msg'] = __('MAIL_ACCOUNT_CREATED_OK',strtolower($_POST['v_account']),$_POST[v_domain],strtolower($_POST['v_account']),$_POST[v_domain]);
+        $_SESSION['ok_msg'] = __('MAIL_ACCOUNT_CREATED_OK',htmlentities(strtolower($_POST['v_account'])),htmlentities($_POST[v_domain]),htmlentities(strtolower($_POST['v_account'])),htmlentities($_POST[v_domain]));
         $_SESSION['ok_msg'] .= " / <a href=".$webmail." target='_blank'>" . __('open webmail') . "</a>";
         unset($v_account);
         unset($v_password);
```
