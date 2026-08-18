# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1490_2
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1490_2`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-45 of the vulnerable file.

<?php
/************************************************************************/
/* ATutor																*/
/************************************************************************/
/* Copyright (c) 2002-2010                                              */
/* Inclusive Design Institute                                           */
/* http://atutor.ca														*/
/*																		*/
/* This program is free software. You can redistribute it and/or        */
/* modify it under the terms of the GNU General Public License          */
/* as published by the Free Software Foundation.                        */
/************************************************************************/
// $Id$

define('AT_INCLUDE_PATH', '../../../include/');
require(AT_INCLUDE_PATH.'vitals.inc.php');
admin_authenticate(AT_ADMIN_PRIV_USERS);
// Prevent remote access via CSRF: 5566
if($_SERVER['HTTP_REFERER'] != $_SERVER['PHP_SELF']){
    $referer_script = preg_replace('#'.$_base_href.'#', '', $_SERVER['HTTP_REFERER']);
    if(!in_array($_pages[$referer_script], $_pages)){
    echo "not a valid referer";
    exit;
    }
}

if (isset($_POST['cancel'])) {
	header('Location: '.AT_BASE_HREF.'mods/_core/users/users.php');
	exit;
}

if (isset($_POST['submit'])) {
	$missing_fields = array();
        $_POST['password']   = $addslashes($_POST['password']);
		$_POST['website']    = $addslashes($_POST['website']);
		$_POST['first_name'] = $addslashes($_POST['first_name']);
		$_POST['second_name']  = $addslashes($_POST['second_name']);
		$_POST['last_name']  = $addslashes($_POST['last_name']);
		$_POST['address']    = $addslashes($_POST['address']);
		$_POST['postal']     = $addslashes($_POST['postal']);
		$_POST['city']       = $addslashes($_POST['city']);
		$_POST['province']   = $addslashes($_POST['province']);
		$_POST['country']    = $addslashes($_POST['country']);
		$_POST['phone']      = $addslashes($_POST['phone']);
		$_POST['status']     = intval($_POST['status']);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,13 +16,8 @@
 require(AT_INCLUDE_PATH.'vitals.inc.php');
 admin_authenticate(AT_ADMIN_PRIV_USERS);
 // Prevent remote access via CSRF: 5566
-if($_SERVER['HTTP_REFERER'] != $_SERVER['PHP_SELF']){
-    $referer_script = preg_replace('#'.$_base_href.'#', '', $_SERVER['HTTP_REFERER']);
-    if(!in_array($_pages[$referer_script], $_pages)){
-    echo "not a valid referer";
-    exit;
-    }
-}
+// Ref include/lib/vitals-inc.php
+check_referer();
 
 if (isset($_POST['cancel'])) {
 	header('Location: '.AT_BASE_HREF.'mods/_core/users/users.php');
```
