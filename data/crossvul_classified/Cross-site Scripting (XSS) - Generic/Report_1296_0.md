# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1296_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1296_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-40 of the vulnerable file.

<?php
/*
	FusionPBX
	Version: MPL 1.1

	The contents of this file are subject to the Mozilla Public License Version
	1.1 (the "License"); you may not use this file except in compliance with
	the License. You may obtain a copy of the License at
	http://www.mozilla.org/MPL/

	Software distributed under the License is distributed on an "AS IS" basis,
	WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
	for the specific language governing rights and limitations under the
	License.

	The Original Code is FusionPBX

	The Initial Developer of the Original Code is
	Mark J Crane <markjcrane@fusionpbx.com>
	Portions created by the Initial Developer are Copyright (C) 2008-2013
	the Initial Developer. All Rights Reserved.

	Contributor(s):
	Mark J Crane <markjcrane@fusionpbx.com>
*/
include "root.php";
require_once "resources/require.php";
require_once "resources/check_auth.php";
if (permission_exists('dialplan_add')
	|| permission_exists('dialplan_edit')
	|| permission_exists('inbound_route_add')
	|| permission_exists('inbound_route_edit')
	|| permission_exists('outbound_route_add')
	|| permission_exists('outbound_route_edit')
	|| permission_exists('fifo_edit')
	|| permission_exists('fifo_add')
	|| permission_exists('time_condition_add')
	|| permission_exists('time_condition_edit')) {
	//access granted
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,31 +17,35 @@
 
 	The Initial Developer of the Original Code is
 	Mark J Crane <markjcrane@fusionpbx.com>
-	Portions created by the Initial Developer are Copyright (C) 2008-2013
+	Portions created by the Initial Developer are Copyright (C) 2008-2019
 	the Initial Developer. All Rights Reserved.
 
 	Contributor(s):
 	Mark J Crane <markjcrane@fusionpbx.com>
 */
-include "root.php";
-require_once "resources/require.php";
-require_once "resources/check_auth.php";
-if (permission_exists('dialplan_add')
-	|| permission_exists('dialplan_edit')
-	|| permission_exists('inbound_route_add')
-	|| permission_exists('inbound_route_edit')
-	|| permission_exists('outbound_route_add')
-	|| permission_exists('outbound_route_edit')
-	|| permission_exists('fifo_edit')
-	|| permission_exists('fifo_add')
-	|| permission_exists('time_condition_add')
-	|| permission_exists('time_condition_edit')) {
-	//access granted
-}
-else {
-	echo "access denied";
-	exit;
-}
+
+//includes
+	include "root.php";
+	require_once "resources/require.php";
+	require_once "resources/check_auth.php";
+
+//check permisions
+	if (permission_exists('dialplan_add')
+		|| permission_exists('dialplan_edit')
+		|| permission_exists('inbound_route_add')
+		|| permission_exists('inbound_route_edit')
+		|| permission_exists('outbound_route_add')
+		|| permission_exists('outbound_route_edit')
+		|| permission_exists('fifo_edit')
+		|| permission_exists('fifo_add')
+		|| permission_exists('time_condition_add')
+		|| permission_exists('time_condition_edit')) {
+		//access granted
+	}
+	else {
+		echo "access denied";
+		exit;
+	}
 
 //add multi-lingual support
 	$language = new text;
@@ -55,11 +59,9 @@
 	else {
 		$action = "add";
 	}
-	$dialplan_uuid = $_REQUEST["dialplan_uuid"];
 
 //get the http values and set them as php variables
-	$app_uuid = $_REQUEST["app_uuid"];
-	if (count($_POST)>0) {
+	if (count($_POST) > 0) {
 		$dialplan_uuid = $_POST["dialplan_uuid"];
 		$dialplan_detail_tag = $_POST["dialplan_detail_tag"];
 		$dialplan_detail_order = $_POST["dialplan_detail_order"];
@@ -68,6 +70,12 @@
 		$dialplan_detail_break = $_POST["dialplan_detail_break"];
 		$dialplan_detail_inline = $_POST["dialplan_detail_inline"];
 		$dialplan_detail_group = $_POST["dialplan_detail_group"];
+	}
+	if (is_uuid($_REQUEST["app_uuid"])) {
+		$app_uuid = $_REQUEST["app_uuid"];
+	}
+	if (is_uuid($_REQUEST["dialplan_uuid"])) {
+		$dialplan_uuid = $_REQUEST["dialplan_uuid"];
 	}
 
 if (count($_POST)>0 && strlen($_POST["persistformvar"]) == 0) {
@@ -491,4 +499,5 @@
 
 //include the footer
 	require_once "resources/footer.php";
+
 ?>
```
