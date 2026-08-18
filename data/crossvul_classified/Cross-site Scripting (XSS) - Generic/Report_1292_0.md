# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1292_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1292_0`)

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
	Portions created by the Initial Developer are Copyright (C) 2008-2018
	the Initial Developer. All Rights Reserved.

	Contributor(s):
	Mark J Crane <markjcrane@fusionpbx.com>
*/

//includes
	require_once "root.php";
	require_once "resources/require.php";
	require_once "resources/check_auth.php";

//check permissions
	if (permission_exists('fax_log_view')) {
		//access granted
	}
	else {
		echo "access denied";
		exit;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,7 +17,7 @@
 
 	The Initial Developer of the Original Code is
 	Mark J Crane <markjcrane@fusionpbx.com>
-	Portions created by the Initial Developer are Copyright (C) 2008-2018
+	Portions created by the Initial Developer are Copyright (C) 2008-2019
 	the Initial Developer. All Rights Reserved.
 
 	Contributor(s):
@@ -42,9 +42,13 @@
 	$language = new text;
 	$text = $language->get();
 
-//get ids
-	$fax_log_uuid = $_REQUEST["id"];
-	$fax_uuid = $_REQUEST["fax_uuid"];
+//validate the uuids
+	if (is_uuid($_REQUEST["id"])) {
+		$fax_log_uuid = $_REQUEST["id"];
+	}
+	if (is_uuid($_REQUEST["fax_uuid"])) {
+		$fax_uuid = $_REQUEST["fax_uuid"];
+	}
 
 //pre-populate the form
 	if (is_uuid($fax_log_uuid) && is_uuid($fax_uuid)) {
@@ -83,7 +87,7 @@
 	require_once "resources/header.php";
 
 //show the content
-	echo "<table cellpadding='0' cellspacing='0' border='0' align='right'><tr><td><input type='button' class='btn' alt='".$text['button-back']."' onclick=\"document.location='fax_logs.php?id=".$fax_uuid."'\" value='".$text['button-back']."'></td></tr></table>";
+	echo "<table cellpadding='0' cellspacing='0' border='0' align='right'><tr><td><input type='button' class='btn' alt='".$text['button-back']."' onclick=\"document.location='fax_logs.php?id=".urlencode($fax_uuid)."'\" value='".$text['button-back']."'></td></tr></table>";
 	echo "<b>".$text['title-fax_log']."</b>\n";
 	echo "<br /><br />\n";
 
@@ -91,32 +95,32 @@
 
 	echo "<tr>\n";
 	echo "<td width='30%' class='vncell' valign='top' nowrap='nowrap'>".$text['label-fax_success']."</td>\n";
-	echo "<td width='70%' class='vtable'>".$fax_success."</td>\n";
+	echo "<td width='70%' class='vtable'>".escape($fax_success)."</td>\n";
 	echo "</tr>\n";
 
 	echo "<tr>\n";
 	echo "<td class='vncell' valign='top' nowrap='nowrap'>".$text['label-fax_result_code']."</td>\n";
-	echo "<td class='vtable'>".$fax_result_code."</td>\n";
+	echo "<td class='vtable'>".escape($fax_result_code)."</td>\n";
 	echo "</tr>\n";
 
 	echo "<tr>\n";
 	echo "<td class='vncell' valign='top' nowrap='nowrap'>".$text['label-fax_result_text']."</td>\n";
-	echo "<td class='vtable'>".$fax_result_text."</td>\n";
+	echo "<td class='vtable'>".escape($fax_result_text)."</td>\n";
 	echo "</tr>\n";
 
 	echo "<tr>\n";
 	echo "<td class='vncell' valign='top' nowrap='nowrap'>".$text['label-fax_file']."</td>\n";
-	echo "<td class='vtable'>".$fax_file."</td>\n";
+	echo "<td class='vtable'>".escape($fax_file)."</td>\n";
 	echo "</tr>\n";
 
 	echo "<tr>\n";
 	echo "<td class='vncell' valign='top' nowrap='nowrap'>".$text['label-fax_ecm_used']."</td>\n";
-	echo "<td class='vtable'>".$fax_ecm_used."</td>\n";
+	echo "<td class='vtable'>".escape($fax_ecm_used)."</td>\n";
 	echo "</tr>\n";
 
 	echo "<tr>\n";
 	echo "<td class='vncell' valign='top' nowrap='nowrap'>".$text['label-fax_local_station_id']."</td>\n";
-	echo "<td class='vtable'>".$fax_local_station_id."</td>\n";
+	echo "<td class='vtable'>".escape($fax_local_station_id)."</td>\n";
 	echo "</tr>\n";
 
 	echo "<tr>\n";
@@ -126,57 +130,57 @@
 
 	echo "<tr>\n";
 	echo "<td class='vncell' valign='top' nowrap='nowrap'>".$text['label-fax_document_total_pages']."</td>\n";
-	echo "<td class='vtable'>".$fax_document_total_pages."</td>\n";
+	echo "<td class='vtable'>".escape($fax_document_total_pages)."</td>\n";
 	echo "</tr>\n";
 
 	echo "<tr>\n";
 	echo "<td class='vncell' valign='top' nowrap='nowrap'>".$text['label-fax_image_resolution']."</td>\n";
-	echo "<td class='vtable'>".$fax_image_resolution."</td>\n";
+	echo "<td class='vtable'>".escape($fax_image_resolution)."</td>\n";
 	echo "</tr>\n";
 
 	echo "<tr>\n";
 	echo "<td class='vncell' valign='top' nowrap='nowrap'>".$text['label-fax_image_size']."</td>\n";
-	echo "<td class='vtable'>".$fax_image_size."</td>\n";
+	echo "<td class='vtable'>".escape($fax_image_size)."</td>\n";
 	echo "</tr>\n";
 
 	echo "<tr>\n";
 	echo "<td class='vncell' valign='top' nowrap='nowrap'>".$text['label-fax_bad_rows']."</td>\n";
-	echo "<td class='vtable'>".$fax_bad_rows."</td>\n";
+	echo "<td class='vtable'>".escape($fax_bad_rows)."</td>\n";
 	echo "</tr>\n";
 
 	echo "<tr>\n";
 	echo "<td class='vncell' valign='top' nowrap='nowrap'>".$text['label-fax_transfer_rate']."</td>\n";
-	echo "<td class='vtable'>".$fax_transfer_rate."</td>\n";
+	echo "<td class='vtable'>".escape($fax_transfer_rate)."</td>\n";
 	echo "</tr>\n";
 
 	echo "<tr>\n";
 	echo "<td class='vncell' valign='top' nowrap='nowrap'>".$text['label-fax_retry_attempts']."</td>\n";
-	echo "<td class='vtable'>".$fax_retry_attempts."</td>\n";
+	echo "<td class='vtable'>".escape($fax_retry_attempts)."</td>\n";
 	echo "</tr>\n";
 
 	echo "<tr>\n";
 	echo "<td class='vncell' valign='top' nowrap='nowrap'>".$text['label-fax_retry_limit']."</td>\n";
-	echo "<td class='vtable'>".$fax_retry_limit."</td>\n";
+	echo "<td class='vtable'>".escape($fax_retry_limit)."</td>\n";
 	echo "</tr>\n";
 
 	echo "<tr>\n";
 	echo "<td class='vncell' valign='top' nowrap='nowrap'>".$text['label-fax_retry_sleep']."</td>\n";
-	echo "<td class='vtable'>".$fax_retry_sleep."</td>\n";
+	echo "<td class='vtable'>".escape($fax_retry_sleep)."</td>\n";
 	echo "</tr>\n";
 
 	echo "<tr>\n";
 	echo "<td class='vncell' valign='top' nowrap='nowrap'>".$text['label-fax_uri']."</td>\n";
-	echo "<td class='vtable'>".$fax_uri."</td>\n";
+	echo "<td class='vtable'>".escape($fax_uri)."</td>\n";
 	echo "</tr>\n";
 
 	echo "<tr>\n";
 	echo "<td class='vncell' valign='top' nowrap='nowrap'>".$text['label-fax_date']."</td>\n";
-	echo "<td class='vtable'>".$fax_date."</td>\n";
+	echo "<td class='vtable'>".escape($fax_date)."</td>\n";
 	echo "</tr>\n";
 
 	echo "<tr>\n";
 	echo "<td class='vncell' valign='top' nowrap='nowrap'>".$text['label-fax_epoch']."</td>\n";
-	echo "<td class='vtable'>".$fax_epoch."</td>\n";
+	echo "<td class='vtable'>".escape($fax_epoch)."</td>\n";
 	echo "</tr>\n";
 
 	echo "</table>";
```
