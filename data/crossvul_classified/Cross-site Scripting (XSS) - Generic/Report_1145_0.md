# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1145_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1145_0`)

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
 Portions created by the Initial Developer are Copyright (C) 2008-2012
 the Initial Developer. All Rights Reserved.

 Contributor(s):
 Mark J Crane <markjcrane@fusionpbx.com>
*/
require_once "root.php";
require_once "resources/require.php";
require_once "resources/check_auth.php";
if (permission_exists('device_setting_view')) {
	//access granted
}
else {
	echo "access denied";
	exit;
}

//add multi-lingual support
	$language = new text;
	$text = $language->get();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,34 +17,43 @@
 
  The Initial Developer of the Original Code is
  Mark J Crane <markjcrane@fusionpbx.com>
- Portions created by the Initial Developer are Copyright (C) 2008-2012
+ Portions created by the Initial Developer are Copyright (C) 2008-2019
  the Initial Developer. All Rights Reserved.
 
  Contributor(s):
  Mark J Crane <markjcrane@fusionpbx.com>
 */
-require_once "root.php";
-require_once "resources/require.php";
-require_once "resources/check_auth.php";
-if (permission_exists('device_setting_view')) {
-	//access granted
-}
-else {
-	echo "access denied";
-	exit;
-}
+
+//includes
+	require_once "root.php";
+	require_once "resources/require.php";
+	require_once "resources/check_auth.php";
+
+//check permissions
+	if (permission_exists('device_setting_view')) {
+		//access granted
+	}
+	else {
+		echo "access denied";
+		exit;
+	}
 
 //add multi-lingual support
 	$language = new text;
 	$text = $language->get();
 
-require_once "resources/header.php";
-require_once "resources/paging.php";
+//additional includes
+	require_once "resources/header.php";
+	require_once "resources/paging.php";
 
 //get variables used to control the order
 	$order_by = $_GET["order_by"];
 	$order = $_GET["order"];
-	$device_uuid = $_GET["id"];
+
+//get the uuid
+	if (is_uuid($_GET['id'])) {
+		$device_uuid = $_GET['id'];
+	}
 
 //show the content
 	echo "<table width='100%' cellpadding='0' cellspacing='0' border='0'>\n";
@@ -107,7 +116,7 @@
 				echo th_order_by('device_setting_description', $text['label-description'], $order_by, $order);
 				echo "<td align='right' width='42'>\n";
 				if (permission_exists('device_setting_add')) {
-					echo "	<a href='device_setting_edit.php?device_uuid=".$_GET['id']."' alt='".$text['button-add']."'>$v_link_label_add</a>\n";
+					echo "	<a href='device_setting_edit.php?device_uuid=".urlencode($device_uuid)."' alt='".$text['button-add']."'>$v_link_label_add</a>\n";
 				}
 				else {
 					echo "	&nbsp;\n";
```
