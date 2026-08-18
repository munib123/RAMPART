# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3324_3
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3324_3`)

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
 * Administration - Site Preferences
 *
 */

require_once ("../class2.php");

if(isset($_POST['newver']))
{
	header("location:http://e107.org/index.php");
	exit();
}

if(!getperms("1"))
{
	e107::redirect('admin');
	exit();
}

e107::coreLan('prefs', true);

$e_sub_cat = 'prefs';
//e107::lan('core','mailout','admin');
e107::coreLan('mailout', true);


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,6 +10,10 @@
  *
  */
 
+if(!empty($_POST) && !isset($_POST['e-token']))
+{
+	$_POST['e-token'] = '';
+}
 require_once ("../class2.php");
 
 if(isset($_POST['newver']))
@@ -309,6 +313,7 @@
 $text = "
 <div id='core-prefs'>
 	<form class='admin-menu' method='post' action='".e_SELF."' autocomplete='off'>
+	<input type='hidden' name='e-token' value='".e_TOKEN."' />
 		<fieldset id='core-prefs-main'>
 			<legend>".PRFLAN_1."</legend>
 			<table class='table adminform'>
```
