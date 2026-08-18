# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1685_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1685_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-32 of the vulnerable file.

<?php
	//only admins can get this
	if(!function_exists("current_user_can") || (!current_user_can("manage_options") && !current_user_can("pmpro_discountcodes")))
	{
		die(__("You do not have permissions to perform this action.", "pmpro"));
	}	
	
	//vars
	global $wpdb, $pmpro_currency_symbol;
	
	if(isset($_REQUEST['edit']))	
		$edit = $_REQUEST['edit'];
	else
		$edit = false;
	
	if(isset($_REQUEST['delete']))
		$delete = $_REQUEST['delete'];
	else
		$delete = false;
		
	if(isset($_REQUEST['saveid']))
		$saveid = $_POST['saveid'];
	else
		$saveid = false;			
	
	if($saveid)
	{
		//get vars
		$code = $_POST['code'];
		$starts_month = $_POST['starts_month'];
		$starts_day = $_POST['starts_day'];
		$starts_year = $_POST['starts_year'];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,31 +9,31 @@
 	global $wpdb, $pmpro_currency_symbol;
 	
 	if(isset($_REQUEST['edit']))	
-		$edit = $_REQUEST['edit'];
+		$edit = intval($_REQUEST['edit']);
 	else
 		$edit = false;
 	
 	if(isset($_REQUEST['delete']))
-		$delete = $_REQUEST['delete'];
+		$delete = intval($_REQUEST['delete']);
 	else
 		$delete = false;
 		
 	if(isset($_REQUEST['saveid']))
-		$saveid = $_POST['saveid'];
+		$saveid = intval($_POST['saveid']);
 	else
 		$saveid = false;			
 	
 	if($saveid)
 	{
 		//get vars
-		$code = $_POST['code'];
-		$starts_month = $_POST['starts_month'];
-		$starts_day = $_POST['starts_day'];
-		$starts_year = $_POST['starts_year'];
-		$expires_month = $_POST['expires_month'];
-		$expires_day = $_POST['expires_day'];
-		$expires_year = $_POST['expires_year'];
-		$uses = $_POST['uses'];
+		$code = sanitize_text_field($_POST['code']);
+		$starts_month = intval($_POST['starts_month']);
+		$starts_day = intval($_POST['starts_day']);
+		$starts_year = intval($_POST['starts_year']);
+		$expires_month = intval($_POST['expires_month']);
+		$expires_day = intval($_POST['expires_day']);
+		$expires_year = intval($_POST['expires_year']);
+		$uses = intval($_POST['uses']);
 		
 		//fix up dates		
 		$starts = date("Y-m-d", strtotime($starts_month . "/" . $starts_day . "/" . $starts_year, current_time("timestamp")));
@@ -110,7 +110,7 @@
 				{
 					//get the values ready
 					$n = array_search($level_id, $all_levels_a); 	//this is the key location of this level's values
-					$initial_payment = $initial_payment_a[$n];
+					$initial_payment = sanitize_text_field($initial_payment_a[$n]);
 					
 					//is this recurring?
 					if(!empty($recurring_a))
@@ -125,10 +125,10 @@
 							
 					if(!empty($recurring))
 					{
-						$billing_amount = $billing_amount_a[$n];
-						$cycle_number = $cycle_number_a[$n];
-						$cycle_period = $cycle_period_a[$n];
-						$billing_limit = $billing_limit_a[$n];
+						$billing_amount = sanitize_text_field($billing_amount_a[$n]);
+						$cycle_number = intval($cycle_number_a[$n]);
+						$cycle_period = sanitize_text_field($cycle_period_a[$n]);
+						$billing_limit = intval($billing_limit_a[$n]);
 						
 						//custom trial
 						if(!empty($custom_trial_a))
@@ -143,8 +143,8 @@
 						
 						if(!empty($custom_trial))
 						{
-							$trial_amount = $trial_amount_a[$n];
-							$trial_limit = $trial_limit_a[$n];
+							$trial_amount = sanitize_text_field($trial_amount_a[$n]);
+							$trial_limit = intval($trial_limit_a[$n]);
 						}
 						else
 						{
@@ -175,8 +175,8 @@
 					
 					if(!empty($expiration))
 					{
-						$expiration_number = $expiration_number_a[$n];
-						$expiration_period = $expiration_period_a[$n];
+						$expiration_number = intval($expiration_number_a[$n]);
+						$expiration_period = sanitize_text_field($expiration_period_a[$n]);
 					}
 					else
 					{
```
