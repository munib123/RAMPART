# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1685_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1685_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-32 of the vulnerable file.

<?php
	//only admins can get this
	if(!function_exists("current_user_can") || (!current_user_can("manage_options") && !current_user_can("pmpro_orderscsv")))
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

	if(isset($_REQUEST['start-month']))
		$start_month = $_REQUEST['start-month'];
	else
		$start_month = "1";

	if(isset($_REQUEST['start-day']))
		$start_day = $_REQUEST['start-day'];
	else
		$start_day = "1";

	if(isset($_REQUEST['start-year']))
		$start_year = $_REQUEST['start-year'];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,52 +9,52 @@
 
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
 
 	if(isset($_REQUEST['start-month']))
-		$start_month = $_REQUEST['start-month'];
+		$start_month = intval($_REQUEST['start-month']);
 	else
 		$start_month = "1";
 
 	if(isset($_REQUEST['start-day']))
-		$start_day = $_REQUEST['start-day'];
+		$start_day = intval($_REQUEST['start-day']);
 	else
 		$start_day = "1";
 
 	if(isset($_REQUEST['start-year']))
-		$start_year = $_REQUEST['start-year'];
+		$start_year = intval($_REQUEST['start-year']);
 	else
 		$start_year = date("Y");
 
 	if(isset($_REQUEST['end-month']))
-		$end_month = $_REQUEST['end-month'];
+		$end_month = intval($_REQUEST['end-month']);
 	else
 		$end_month = date("n");
 
 	if(isset($_REQUEST['end-day']))
-		$end_day = $_REQUEST['end-day'];
+		$end_day = intval($_REQUEST['end-day']);
 	else
 		$end_day = date("j");
 
 	if(isset($_REQUEST['end-year']))
-		$end_year = $_REQUEST['end-year'];
+		$end_year = intval($_REQUEST['end-year']);
 	else
 		$end_year = date("Y");
 
 	if(isset($_REQUEST['predefined-date']))
-		$predefined_date = $_REQUEST['predefined-date'];
+		$predefined_date = sanitize_text_field($_REQUEST['predefined-date']);
 	else
 		$predefined_date = "This Month";
 
 	if(isset($_REQUEST['status']))
-		$status = $_REQUEST['status'];
+		$status = sanitize_text_field($_REQUEST['status']);
 	else
 		$status = "";
 
```
