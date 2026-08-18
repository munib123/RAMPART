# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1490_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1490_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-44 of the vulnerable file.

<?php
/****************************************************************************/
/* ATutor																	*/
/****************************************************************************/
/* Copyright (c) 2002-2010                                                  */
/* Inclusive Design Institute                                               */
/* http://atutor.ca															*/
/*																			*/
/* This program is free software. You can redistribute it and/or			*/
/* modify it under the terms of the GNU General Public License				*/
/* as published by the Free Software Foundation.							*/
/****************************************************************************/
// $Id$

define('AT_INCLUDE_PATH', '../../../../include/');
require(AT_INCLUDE_PATH.'vitals.inc.php');
admin_authenticate(AT_ADMIN_PRIV_ADMIN);
if($_SERVER['HTTP_REFERER'] != $_SERVER['PHP_SELF']){
    $referer_script = preg_replace('#'.$_base_href.'#', '', $_SERVER['HTTP_REFERER']);
    if(!in_array($_pages[$referer_script], $_pages)){
    echo "not a valid referer";
    exit;
    }
}

if (isset($_POST['cancel'])) {
	$msg->addFeedback('CANCELLED');
	header('Location: index.php');
	exit;
} else if (isset($_POST['submit'])) {
	$missing_fields = array();

	/* login validation */
	if ($_POST['login'] == '') {
		$missing_fields[] = _AT('login_name');
	} else {
		/* check for special characters */
		if (!(preg_match("/^[a-zA-Z0-9_]([a-zA-Z0-9_])*$/i", $_POST['login']))) {
			$msg->addError('LOGIN_CHARS');
		} else {
			$sql = "SELECT * FROM %smembers WHERE login='%s'";
			$rows_members = queryDB($sql,array(TABLE_PREFIX, $_POST['login']));
			if(count($rows_members) != 0){
				$msg->addError('LOGIN_EXISTS');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,13 +15,9 @@
 define('AT_INCLUDE_PATH', '../../../../include/');
 require(AT_INCLUDE_PATH.'vitals.inc.php');
 admin_authenticate(AT_ADMIN_PRIV_ADMIN);
-if($_SERVER['HTTP_REFERER'] != $_SERVER['PHP_SELF']){
-    $referer_script = preg_replace('#'.$_base_href.'#', '', $_SERVER['HTTP_REFERER']);
-    if(!in_array($_pages[$referer_script], $_pages)){
-    echo "not a valid referer";
-    exit;
-    }
-}
+// Prevent remote access via CSRF: 5566
+// Ref include/lib/vitals-inc.php
+check_referer();
 
 if (isset($_POST['cancel'])) {
 	$msg->addFeedback('CANCELLED');
```
