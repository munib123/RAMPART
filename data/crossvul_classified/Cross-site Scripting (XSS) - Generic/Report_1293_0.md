# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1293_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1293_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 28-68 of the vulnerable file.

	include "root.php";
	require_once "resources/require.php";
	require_once "resources/check_auth.php";
	require_once "resources/paging.php";

//check permissions
	if (permission_exists('dialplan_view')) {
		//access granted
	}
	else {
		echo "access denied";
		exit;
	}

//add multi-lingual support
	$language = new text;
	$text = $language->get();

//get posted data
	if (is_array($_POST['dialplans'])) {
		$app_uuid = $_POST['app_uuid'];
		$action = $_POST['action'];
		$dialplans = $_POST['dialplans'];
		$search = $_POST['search'];
		$order_by = $_POST['order_by'];
		$order = $_POST['order'];
	}

//process action
	if ($action && is_array($dialplans) && @sizeof($dialplans) != 0) {

		//define redirect parameters and url
			if (is_uuid($app_uuid)) { $params[] = "app_uuid=".urlencode($app_uuid); }
			if ($search) { $params[] = "search=".urlencode($search); }
			if ($order_by) { $params[] = "order_by=".urlencode($order_by); }
			if ($order) { $params[] = "order=".urlencode($order); }
			$redirect_url = 'dialplans.php'.($params ? '?'.implode('&', $params) : null);
			unset($params);

		//copy the dialplans
			if ($action == 'copy') {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,12 +45,16 @@
 
 //get posted data
 	if (is_array($_POST['dialplans'])) {
-		$app_uuid = $_POST['app_uuid'];
 		$action = $_POST['action'];
 		$dialplans = $_POST['dialplans'];
 		$search = $_POST['search'];
 		$order_by = $_POST['order_by'];
 		$order = $_POST['order'];
+	}
+
+//get the app uuid
+	if (is_uuid($_REQUEST["app_uuid"])) {
+		$app_uuid = $_REQUEST["app_uuid"];
 	}
 
 //process action
@@ -97,9 +101,6 @@
 //get order and order by and sanatize the values
 	$order_by = $_GET["order_by"];
 	$order = $_GET["order"];
-
-//get the app uuid
-	$app_uuid = $_GET["app_uuid"];
 
 //make sure all dialplans with context of public have the inbound route app_uuid
 	if ($app_uuid == 'c03b422e-13a8-bd1b-e42b-b6b9b4d27ce4') {
@@ -161,7 +162,7 @@
 
 //prepare the paging
 	$rows_per_page = ($_SESSION['domain']['paging']['numeric'] != '') ? $_SESSION['domain']['paging']['numeric'] : 50;
-	if (is_uuid($app_uuid)) { $params[] = "app_uuid=".$app_uuid; }
+	$params[] = "app_uuid=".$app_uuid;
 	if ($search) { $params[] = "search=".$search; }
 	if ($order_by) { $params[] = "order_by=".$order_by; }
 	if ($order) { $params[] = "order=".$order; }
@@ -283,7 +284,7 @@
 	}
 	echo 		"<input type='text' class='txt list-search' name='search' id='search' value=\"".escape($search)."\" placeholder=\"".$text['label-search']."\" onkeydown='list_search_reset();'>";
 	echo button::create(['label'=>$text['button-search'],'icon'=>$_SESSION['theme']['button_icon_search'],'type'=>'submit','id'=>'btn_search','style'=>($search != '' ? 'display: none;' : null)]);
-	if (is_uuid($app_uuid)) { $params[] = "app_uuid=".urlencode($app_uuid); }
+	$params[] = "app_uuid=".urlencode($app_uuid);
 	if ($order_by) { $params[] = "order_by=".urlencode($order_by); }
 	if ($order) { $params[] = "order=".urlencode($order); }
 	if ($_GET['show'] && permission_exists('dialplan_all')) { $params[] = "show=".urlencode($_GET['show']); }
@@ -356,7 +357,9 @@
 		foreach ($dialplans as $row) {
 
 			//get the application id
-			$app_uuid = $row['app_uuid'];
+			if (is_uuid($row['app_uuid'])) {
+				$app_uuid = $row['app_uuid'];
+			}
 
 			// blank app id if doesn't match others, so will return to dialplan manager
 			switch ($app_uuid) {
```
