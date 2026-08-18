# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3813_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3813_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 1-18 of the vulnerable file.

<?php
/**
 * Copyright (c) 2011 Robin Appelman <icewind@owncloud.com>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

$tmpl = new OCP\Template( 'files_encryption', 'settings');
$blackList=explode(',',OCP\Config::getAppValue('files_encryption','type_blacklist','jpg,png,jpeg,avi,mpg,mpeg,mkv,mp3,oga,ogv,ogg'));
$enabled=(OCP\Config::getAppValue('files_encryption','enable_encryption','true')=='true');
$tmpl->assign('blacklist',$blackList);
$tmpl->assign('encryption_enabled',$enabled);

OCP\Util::addscript('files_encryption','settings');
OCP\Util::addscript('core','multiselect');

return $tmpl->fetchPage();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,8 @@
  * later.
  * See the COPYING-README file.
  */
+
+OC_Util::checkAdminUser();
 
 $tmpl = new OCP\Template( 'files_encryption', 'settings');
 $blackList=explode(',',OCP\Config::getAppValue('files_encryption','type_blacklist','jpg,png,jpeg,avi,mpg,mpeg,mkv,mp3,oga,ogv,ogg'));
```
