# CrossVul Fix Pair: Credentials Management Errors in php
**Pair ID:** 3797_1
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3797_1`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```php
Lines 1-27 of the vulnerable file.

<?php
/**
 * Copyright (c) 2012 Frank Karlitschek frank@owncloud.org
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
*/

$RUNTIME_NOAPPS = TRUE; //no apps
require_once '../../lib/base.php';

// Someone wants to reset their password:
if(isset($_GET['token']) && isset($_GET['user']) && OC_Preferences::getValue($_GET['user'], 'owncloud', 'lostpassword') === $_GET['token']) {
	if (isset($_POST['password'])) {
		if (OC_User::setPassword($_GET['user'], $_POST['password'])) {
			OC_Preferences::deleteKey($_GET['user'], 'owncloud', 'lostpassword');
			OC_Template::printGuestPage('core/lostpassword', 'resetpassword', array('success' => true));
		} else {
			OC_Template::printGuestPage('core/lostpassword', 'resetpassword', array('success' => false));
		}
	} else {
		OC_Template::printGuestPage('core/lostpassword', 'resetpassword', array('success' => false));
	}
} else {
	// Someone lost their password
	OC_Template::printGuestPage('core/lostpassword', 'lostpassword', array('error' => false, 'requested' => false));
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,7 +10,7 @@
 require_once '../../lib/base.php';
 
 // Someone wants to reset their password:
-if(isset($_GET['token']) && isset($_GET['user']) && OC_Preferences::getValue($_GET['user'], 'owncloud', 'lostpassword') === $_GET['token']) {
+if(isset($_GET['token']) && isset($_GET['user']) && OC_Preferences::getValue($_GET['user'], 'owncloud', 'lostpassword') === hash("sha256", $_GET['token'])) {
 	if (isset($_POST['password'])) {
 		if (OC_User::setPassword($_GET['user'], $_POST['password'])) {
 			OC_Preferences::deleteKey($_GET['user'], 'owncloud', 'lostpassword');
```
