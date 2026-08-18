# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1685_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1685_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-37 of the vulnerable file.

<?php
	//only admins can get this
	if(!function_exists("current_user_can") || (!current_user_can("manage_options") && !current_user_can("pmpro_membershiplevels")))
	{
		die(__("You do not have permissions to perform this action.", "pmpro"));
	}	
	
	global $wpdb, $msg, $msgt, $pmpro_currency_symbol;

	//some vars
	$gateway = pmpro_getOption("gateway");
    $pmpro_level_order = pmpro_getOption('level_order');

	global $pmpro_stripe_error, $pmpro_braintree_error, $pmpro_payflow_error, $pmpro_twocheckout_error, $wp_version;
	
	if(isset($_REQUEST['edit']))
		$edit = $_REQUEST['edit'];	
	else
		$edit = false;
	if(isset($_REQUEST['copy']))
		$copy = $_REQUEST['copy'];
	if(isset($_REQUEST['s']))
		$s = $_REQUEST['s'];
	else
		$s = "";
	
	if(isset($_REQUEST['action']))
		$action = $_REQUEST['action'];
	else
		$action = false;
		
	if(isset($_REQUEST['saveandnext']))
		$saveandnext = $_REQUEST['saveandnext'];

	if(isset($_REQUEST['saveid']))
		$saveid = $_REQUEST['saveid'];
	if(isset($_REQUEST['deleteid']))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,28 +14,28 @@
 	global $pmpro_stripe_error, $pmpro_braintree_error, $pmpro_payflow_error, $pmpro_twocheckout_error, $wp_version;
 	
 	if(isset($_REQUEST['edit']))
-		$edit = $_REQUEST['edit'];	
+		$edit = intval($_REQUEST['edit']);
 	else
 		$edit = false;
 	if(isset($_REQUEST['copy']))
-		$copy = $_REQUEST['copy'];
+		$copy = intval($_REQUEST['copy']);
 	if(isset($_REQUEST['s']))
-		$s = $_REQUEST['s'];
+		$s = sanitize_text_field($_REQUEST['s']);
 	else
 		$s = "";
 	
 	if(isset($_REQUEST['action']))
-		$action = $_REQUEST['action'];
+		$action = sanitize_text_field($_REQUEST['action']);
 	else
 		$action = false;
 		
 	if(isset($_REQUEST['saveandnext']))
-		$saveandnext = $_REQUEST['saveandnext'];
+		$saveandnext = intval($_REQUEST['saveandnext']);
 
 	if(isset($_REQUEST['saveid']))
-		$saveid = $_REQUEST['saveid'];
+		$saveid = intval($_REQUEST['saveid']);
 	if(isset($_REQUEST['deleteid']))
-		$deleteid = $_REQUEST['deleteid'];
+		$deleteid = intval($_REQUEST['deleteid']);
 
 	if($action == "save_membershiplevel")
 	{
@@ -155,7 +155,7 @@
 	{
 		global $wpdb;
 
-		$ml_id = $_REQUEST['deleteid'];
+		$ml_id = intval($_REQUEST['deleteid']);
 	  
 		if($ml_id > 0)
 		{	  
@@ -280,7 +280,7 @@
 			
 		?>
 		<form action="" method="post" enctype="multipart/form-data">
-			<input name="saveid" type="hidden" value="<?php echo $edit?>" />
+			<input name="saveid" type="hidden" value="<?php echo esc_attr($edit); ?>" />
 			<input type="hidden" name="action" value="save_membershiplevel" />
 			<table class="form-table">
 			<tbody>
@@ -571,7 +571,7 @@
 		<p class="search-box">
 			<label class="screen-reader-text" for="post-search-input"><?php _e('Search Levels', 'pmpro');?>:</label>
 			<input type="hidden" name="page" value="pmpro-membershiplevels" />
-			<input id="post-search-input" type="text" value="<?php echo $s?>" name="s" size="30" />
+			<input id="post-search-input" type="text" value="<?php echo esc_attr($s); ?>" name="s" size="30" />
 			<input class="button" type="submit" value="<?php _e('Search Levels', 'pmpro');?>" id="search-submit" />
 		</p>
 	</form>	
```
