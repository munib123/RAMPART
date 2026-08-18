# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3739_7
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3739_7`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-20 of the vulnerable file.

<?php
/**
 * Copyright (c) 2011 Bart Visscher <bartv@thisnet.nl>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */
 

OCP\JSON::checkLoggedIn();
OCP\JSON::checkAppEnabled('calendar');

$id = $_POST['id'];
$access = OC_Calendar_App::getaccess($id, OC_Calendar_App::EVENT);
if($access != 'owner' && $access != 'rw'){
	OCP\JSON::error(array('message'=>'permission denied'));
	exit;
}
$result = OC_Calendar_Object::delete($id);
OCP\JSON::success();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,7 @@
 
 OCP\JSON::checkLoggedIn();
 OCP\JSON::checkAppEnabled('calendar');
+OCP\JSON::callCheck();
 
 $id = $_POST['id'];
 $access = OC_Calendar_App::getaccess($id, OC_Calendar_App::EVENT);
```
