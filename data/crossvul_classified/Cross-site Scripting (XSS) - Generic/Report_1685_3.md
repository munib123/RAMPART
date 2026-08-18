# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1685_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1685_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-32 of the vulnerable file.

<?php
	//only admins can get this
	if(!function_exists("current_user_can") || (!current_user_can("manage_options") && !current_user_can("pmpro_memberslistcsv")))
	{
		die(__("You do not have permissions to perform this action.", "pmpro"));
	}

	global $wpdb;

	//get users
	if(isset($_REQUEST['s']))
		$s = $_REQUEST['s'];
	else
		$s = "";

	if(isset($_REQUEST['l']))
		$l = $_REQUEST['l'];
	else
		$l = false;

	//some vars for the search
	if(!empty($_REQUEST['pn']))
		$pn = intval($_REQUEST['pn']);
	else
		$pn = 1;

	if(!empty($_REQUEST['limit']))
		$limit = intval($_REQUEST['limit']);
	else
		$limit = false;

	if($limit)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,12 +9,12 @@
 
 	//get users
 	if(isset($_REQUEST['s']))
-		$s = $_REQUEST['s'];
+		$s = sanitize_text_field($_REQUEST['s']);
 	else
 		$s = "";
 
 	if(isset($_REQUEST['l']))
-		$l = $_REQUEST['l'];
+		$l = intval($_REQUEST['l']);
 	else
 		$l = false;
 
```
