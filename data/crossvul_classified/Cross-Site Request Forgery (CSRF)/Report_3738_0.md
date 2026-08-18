# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3738_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3738_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-30 of the vulnerable file.

<?php
/**
 * Copyright (c) 2011, Robin Appelman <icewind1991@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or later.
 * See the COPYING-README file.
 */

require_once ("../../lib/base.php");
OC_Util::checkAdminUser();

$action=isset($_POST['action'])?$_POST['action']:$_GET['action'];
$result=false;
switch($action){
	case 'getValue':
		$result=OC_Appconfig::getValue($_GET['app'],$_GET['key'],$_GET['defaultValue']);
		break;
	case 'setValue':
		$result=OC_Appconfig::setValue($_POST['app'],$_POST['key'],$_POST['value']);
		break;
	case 'getApps':
		$result=OC_Appconfig::getApps();
		break;
	case 'getKeys':
		$result=OC_Appconfig::getKeys($_GET['app']);
		break;
	case 'hasKey':
		$result=OC_Appconfig::hasKey($_GET['app'],$_GET['key']);
		break;
	case 'deleteKey':
		$result=OC_Appconfig::deleteKey($_POST['app'],$_POST['key']);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,6 +7,7 @@
 
 require_once ("../../lib/base.php");
 OC_Util::checkAdminUser();
+OCP\JSON::callCheck();
 
 $action=isset($_POST['action'])?$_POST['action']:$_GET['action'];
 $result=false;
```
