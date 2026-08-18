# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3324_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3324_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-41 of the vulnerable file.

<?php
/*
 * e107 website system
 *
 * Copyright (C) 2008-2015 e107 Inc (e107.org)
 * Released under the terms and conditions of the
 * GNU General Public License (http://www.gnu.org/licenses/gpl.txt)
 *
 * Administration Area - Front page
 *
*/

/**
 *	e107 Front page administration
 *
 *	@package	e107
 *	@subpackage	admin
 *	@version 	$Id$;
 */

require_once ('../class2.php');
if(! getperms('G'))
{
	e107::redirect('admin');
	exit();
}

e107::coreLan('frontpage', true);

$e_sub_cat = 'frontpage';
require_once ('auth.php');

$mes = e107::getMessage();

$frontPref = e107::pref('core');              		 	// Get prefs

// Get list of possible options for front page
$front_page['news'] = array('page' => 'news.php', 'title' => ADLAN_0); // TODO Move to e107_plugins/news

$front_page['wmessage'] = array('page' => 'index.php', 'title' => ADLAN_28, 'diz'=>'index.php');

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,6 +18,10 @@
  *	@version 	$Id$;
  */
 
+if(!empty($_POST) && !isset($_POST['e-token']))
+{
+	$_POST['e-token'] = '';
+}
 require_once ('../class2.php');
 if(! getperms('G'))
 {
@@ -392,6 +396,7 @@
 		$show_legend = $show_button ? " class='e-hideme'" : '';
 		$text = "
 		<form method='post' action='".e_SELF."'>
+		<input type='hidden' name='e-token' value='".e_TOKEN."' />
 			<fieldset id='frontpage-settings'>
 				<legend{$show_legend}>".FRTLAN_13."</legend>
 
@@ -494,7 +499,9 @@
 // <legend class='e-hideme'>".($rule_info['order'] ? FRTLAN_46 : FRTLAN_42)."</legend>
 
 		$text = "
-		<form method='post' action='".e_SELF."'>";
+		<form method='post' action='".e_SELF."'>
+		<input type='hidden' name='e-token' value='".e_TOKEN."' />
+		";
 		
 		$text .= '<ul class="nav nav-tabs" id="myTabs">
 			<li class="active"><a data-toggle="tab" href="#home">'.FRTLAN_49.'</a></li>
```
