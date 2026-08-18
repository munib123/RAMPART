# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3775_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3775_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 1-29 of the vulnerable file.

<?php
/**
 * Copyright (c) 2011, Robin Appelman <icewind1991@gmail.com>
 * This file is licensed under the Affero General Public License version 3 or later.
 * See the COPYING-README file.
 */

require_once ("../../lib/base.php");
OC_JSON::checkLoggedIn();
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
@@ -6,6 +6,7 @@
  */
 
 require_once ("../../lib/base.php");
+OC_Util::checkAdminUser();
 OC_JSON::checkLoggedIn();
 $action=isset($_POST['action'])?$_POST['action']:$_GET['action'];
 $result=false;
```
