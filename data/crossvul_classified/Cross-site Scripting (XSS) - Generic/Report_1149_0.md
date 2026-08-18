# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1149_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1149_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-36 of the vulnerable file.

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
	Portions created by the Initial Developer are Copyright (C) 2018
	the Initial Developer. All Rights Reserved.
	Contributor(s):
	Mark J Crane <markjcrane@fusionpbx.com>
*/

//includes
	require_once "root.php";
	require_once "resources/require.php";
	require_once "resources/check_auth.php";

//check permissions
	if (!permission_exists('access_control_node_view')) {
		echo "access denied"; exit;
	}

//add multi-lingual support
	$language = new text;
	$text = $language->get();

//get variables used to control the order
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,7 +13,7 @@
 	The Original Code is FusionPBX
 	The Initial Developer of the Original Code is
 	Mark J Crane <markjcrane@fusionpbx.com>
-	Portions created by the Initial Developer are Copyright (C) 2018
+	Portions created by the Initial Developer are Copyright (C) 2019
 	the Initial Developer. All Rights Reserved.
 	Contributor(s):
 	Mark J Crane <markjcrane@fusionpbx.com>
@@ -26,7 +26,8 @@
 
 //check permissions
 	if (!permission_exists('access_control_node_view')) {
-		echo "access denied"; exit;
+		echo "access denied";
+		exit;
 	}
 
 //add multi-lingual support
@@ -87,7 +88,7 @@
 	echo th_order_by('node_description', $text['label-node_description'], $order_by, $order);
 	echo "<td class='list_control_icons'>";
 	if (permission_exists('access_control_node_add')) {
-		echo "<a href='access_control_node_edit.php?access_control_uuid=".escape($_GET['id'])."' alt='".$text['button-add']."'>$v_link_label_add</a>";
+		echo "<a href='access_control_node_edit.php?access_control_uuid=".urlencode($_GET['id'])."' alt='".$text['button-add']."'>$v_link_label_add</a>";
 	}
 	else {
 		echo "&nbsp;\n";
@@ -98,7 +99,7 @@
 	if (is_array($access_control_nodes)) {
 		foreach($access_control_nodes as $row) {
 			if (permission_exists('access_control_node_edit')) {
-				$tr_link = "href='access_control_node_edit.php?access_control_uuid=".escape($row['access_control_uuid'])."&id=".escape($row['access_control_node_uuid'])."'";
+				$tr_link = "href='access_control_node_edit.php?access_control_uuid=".urlencode($row['access_control_uuid'])."&id=".urlencode($row['access_control_node_uuid'])."'";
 			}
 			echo "<tr ".$tr_link.">\n";
 			echo "	<td valign='top' class='".$row_style[$c]."'>".escape($row['node_type'])."&nbsp;</td>\n";
@@ -107,10 +108,10 @@
 			echo "	<td valign='top' class='".$row_style[$c]."'>".escape($row['node_description'])."&nbsp;</td>\n";
 			echo "	<td class='list_control_icons'>";
 			if (permission_exists('access_control_node_edit')) {
-				echo "<a href='access_control_node_edit.php?access_control_uuid=".escape($row['access_control_uuid'])."&id=".escape($row['access_control_node_uuid'])."' alt='".$text['button-edit']."'>$v_link_label_edit</a>";
+				echo "<a href='access_control_node_edit.php?access_control_uuid=".urlencode($row['access_control_uuid'])."&id=".urlencode($row['access_control_node_uuid'])."' alt='".$text['button-edit']."'>$v_link_label_edit</a>";
 			}
 			if (permission_exists('access_control_node_delete')) {
-				echo "<a href='access_control_node_delete.php?access_control_uuid=".escape($row['access_control_uuid'])."&id=".escape($row['access_control_node_uuid'])."' alt='".$text['button-delete']."' onclick=\"return confirm('".$text['confirm-delete']."')\">$v_link_label_delete</a>";
+				echo "<a href='access_control_node_delete.php?access_control_uuid=".urlencode($row['access_control_uuid'])."&id=".urlencode($row['access_control_node_uuid'])."' alt='".$text['button-delete']."' onclick=\"return confirm('".$text['confirm-delete']."')\">$v_link_label_delete</a>";
 			}
 			echo "	</td>\n";
 			echo "</tr>\n";
@@ -122,7 +123,7 @@
 	echo "</table>\n";
 	if (permission_exists('access_control_node_add')) {
 		echo "<div style='float: right;'>\n";
-		echo "	<a href='access_control_node_edit.php?access_control_uuid=".escape($_GET['id'])."' alt='".$text['button-add']."'>$v_link_label_add</a>";
+		echo "	<a href='access_control_node_edit.php?access_control_uuid=".urlencode($_GET['id'])."' alt='".$text['button-add']."'>$v_link_label_add</a>";
 		echo "</div>\n";
 	}
 	echo "<br />\n";
```
