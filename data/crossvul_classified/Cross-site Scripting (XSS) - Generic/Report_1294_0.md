# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1294_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1294_0`)

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
	include "root.php";
	require_once "resources/require.php";
	require_once "resources/check_auth.php";

//check permissions
	if (permission_exists('voicemail_greeting_edit')) {
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
@@ -42,13 +42,15 @@
 	$language = new text;
 	$text = $language->get();
 
-//get greeting id
+//validate the uuids
 	if (is_uuid($_REQUEST["id"])) {
 		$voicemail_greeting_uuid = $_REQUEST["id"];
 	}
+	if (is_uuid($_REQUEST["voicemail_id"])) {
+		$voicemail_id = $_REQUEST["voicemail_id"];
+	}
 
 //get the form value and set to php variables
-	$voicemail_id = $_REQUEST["voicemail_id"];
 	if (count($_POST) > 0) {
 		$greeting_name = $_POST["greeting_name"];
 		$greeting_description = $_POST["greeting_description"];
@@ -58,8 +60,6 @@
 	}
 
 if (count($_POST) > 0 && strlen($_POST["persistformvar"]) == 0) {
-	//get greeting uuid to edit
-		$voicemail_greeting_uuid = $_POST["voicemail_greeting_uuid"];
 
 	//validate the token
 		$token = new token;
@@ -107,7 +107,6 @@
 
 //pre-populate the form
 	if (count($_GET) > 0 && $_POST["persistformvar"] != "true") {
-		$voicemail_greeting_uuid = $_GET["id"];
 		$sql = "select * from v_voicemail_greetings ";
 		$sql .= "where domain_uuid = :domain_uuid ";
 		$sql .= "and voicemail_greeting_uuid = :voicemail_greeting_uuid ";
@@ -136,7 +135,7 @@
 	echo "<table cellpadding='0' cellspacing='0' border='0' align='right'>\n";
 	echo "<tr>\n";
 	echo "<td nowrap='nowrap'>\n";
-	echo "	<input type='button' class='btn' name='' alt='".$text['button-back']."' onclick=\"window.location='voicemail_greetings.php?id=".$voicemail_id."'\" value='".$text['button-back']."'>";
+	echo "	<input type='button' class='btn' name='' alt='".$text['button-back']."' onclick=\"window.location='voicemail_greetings.php?id=".urlencode($voicemail_id)."'\" value='".$text['button-back']."'>";
 	echo "	<input type='submit' name='submit' class='btn' value='".$text['button-save']."'>\n";
 	echo "</td>\n";
 	echo "</tr>\n";
```
