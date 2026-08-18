# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3324_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3324_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-33 of the vulnerable file.

<?php
/*
 * e107 website system
 *
 * Copyright (C) 2008-2013 e107 Inc (e107.org)
 * Released under the terms and conditions of the
 * GNU General Public License (http://www.gnu.org/licenses/gpl.txt)
 *
 * Administration Area - Meta Tags
 *
 *
*/
require_once("../class2.php");

if (!getperms("T")) 
{
	e107::redirect('admin');
	exit;
}

e107::coreLan('meta', true);

$e_sub_cat = 'meta';
require_once("auth.php");

$mes = e107::getMessage();
$frm = e107::getForm();
$ns = e107::getRender();

if (isset($_POST['metasubmit']))
{
	$tmp = $pref['meta_tag'];
	$langs = explode(",",e_LANLIST);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,6 +10,10 @@
  *
  *
 */
+if(!empty($_POST) && !isset($_POST['e-token']))
+{
+	$_POST['e-token'] = '';
+}
 require_once("../class2.php");
 
 if (!getperms("T")) 
@@ -128,6 +132,7 @@
 			<div class='buttons-bar center'>".
 				$frm->admin_button('metasubmit','no-value','update', LAN_UPDATE)."
 			</div>
+			<input type='hidden' name='e-token' value='".e_TOKEN."' />
 		</fieldset>
 	</form>
 ";
```
