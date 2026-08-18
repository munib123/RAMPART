# CrossVul Fix Pair: Credentials Management Errors in php
**Pair ID:** 3797_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3797_0`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```php
Lines 1-35 of the vulnerable file.

<?php
/**
 * Copyright (c) 2012 Frank Karlitschek frank@owncloud.org
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
*/

$RUNTIME_NOAPPS = TRUE; //no apps
require_once '../../lib/base.php';


// Someone lost their password:
if (isset($_POST['user'])) {
	if (OC_User::userExists($_POST['user'])) {
		$token = hash("sha256", $_POST['user'].OC_Util::generate_random_bytes(10));
		OC_Preferences::setValue($_POST['user'], 'owncloud', 'lostpassword', $token);
		$email = OC_Preferences::getValue($_POST['user'], 'settings', 'email', '');
		if (!empty($email)) {
			$link = OC_Helper::linkToAbsolute('core/lostpassword', 'resetpassword.php', array('user' => $_POST['user'], 'token' => $token));
			$tmpl = new OC_Template('core/lostpassword', 'email');
			$tmpl->assign('link', $link, false);
			$msg = $tmpl->fetchPage();
			$l = OC_L10N::get('core');
			$from = 'lostpassword-noreply@' . OCP\Util::getServerHost();
			OC_MAIL::send($email, $_POST['user'], $l->t('ownCloud password reset'), $msg, $from, 'ownCloud');
			echo('sent');
		}
		OC_Template::printGuestPage('core/lostpassword', 'lostpassword', array('error' => false, 'requested' => true));
	} else {
		OC_Template::printGuestPage('core/lostpassword', 'lostpassword', array('error' => true, 'requested' => false));
	}
} else {
	OC_Template::printGuestPage('core/lostpassword', 'lostpassword', array('error' => false, 'requested' => false));
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,8 +13,8 @@
 // Someone lost their password:
 if (isset($_POST['user'])) {
 	if (OC_User::userExists($_POST['user'])) {
-		$token = hash("sha256", $_POST['user'].OC_Util::generate_random_bytes(10));
-		OC_Preferences::setValue($_POST['user'], 'owncloud', 'lostpassword', $token);
+		$token = hash("sha256", OC_Util::generate_random_bytes(30).OC_Config::getValue('passwordsalt', ''));
+		OC_Preferences::setValue($_POST['user'], 'owncloud', 'lostpassword', hash("sha256", $token)); // Hash the token again to prevent timing attacks
 		$email = OC_Preferences::getValue($_POST['user'], 'settings', 'email', '');
 		if (!empty($email)) {
 			$link = OC_Helper::linkToAbsolute('core/lostpassword', 'resetpassword.php', array('user' => $_POST['user'], 'token' => $token));
```
