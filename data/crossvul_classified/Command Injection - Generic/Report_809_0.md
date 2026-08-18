# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in php
**Pair ID:** 809_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `809_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

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
	Portions created by the Initial Developer are Copyright (C) 2008-2016
	the Initial Developer. All Rights Reserved.

	Contributor(s):
	Mark J Crane <markjcrane@fusionpbx.com>
*/
include "root.php";
require_once "resources/require.php";
require_once "resources/check_auth.php";
if (permission_exists("backup_download")) {
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
@@ -17,22 +17,25 @@
 
 	The Initial Developer of the Original Code is
 	Mark J Crane <markjcrane@fusionpbx.com>
-	Portions created by the Initial Developer are Copyright (C) 2008-2016
+	Portions created by the Initial Developer are Copyright (C) 2008-2019
 	the Initial Developer. All Rights Reserved.
 
 	Contributor(s):
 	Mark J Crane <markjcrane@fusionpbx.com>
 */
-include "root.php";
-require_once "resources/require.php";
-require_once "resources/check_auth.php";
-if (permission_exists("backup_download")) {
-	//access granted
-}
-else {
-	echo "access denied";
-	exit;
-}
+//includes
+	include "root.php";
+	require_once "resources/require.php";
+	require_once "resources/check_auth.php";
+
+//check permissions
+	if (permission_exists("backup_download")) {
+		//access granted
+	}
+	else {
+		echo "access denied";
+		exit;
+	}
 
 //add multi-lingual support
 	$language = new text;
@@ -40,8 +43,9 @@
 
 //download the backup
 	if ($_GET['a'] == "download" && permission_exists('backup_download')) {
-		$file_format = $_GET['file_format'];
-		$file_format = ($file_format != '') ? $file_format : 'tgz';
+		//get the file format
+			$file_format = $_GET['file_format'];
+			$file_format = ($file_format != '') ? $file_format : 'tgz';
 
 		//build the backup file
 			$backup_path = ($_SESSION['server']['backup']['path'] != '') ? $_SESSION['server']['backup']['path'] : '/tmp';
@@ -55,8 +59,12 @@
 					default : $cmd = 'tar -zvcf ';
 				}
 				$cmd .= $backup_path.'/'.$backup_file.' ';
-				if (isset($_SESSION['backup']['path'])) foreach ($_SESSION['backup']['path'] as $value) {
-					$cmd .= $value.' ';
+				if (isset($_SESSION['backup']['path'])) {
+					foreach ($_SESSION['backup']['path'] as $value) {
+						if (file_exists($value)) {
+							$cmd .= $value.' ';
+						}
+					}
 				}
 				$cmd .= " 2>&1";
 				exec($cmd, $response, $restore_errlevel);
@@ -109,7 +117,7 @@
 		$backup_path = ($_SESSION['server']['backup']['path'] != '') ? $_SESSION['server']['backup']['path'] : '/tmp';
 		$backup_file = $_FILES['backup_file']['name'];
 
-		if (is_uploaded_file($_FILES['backup_file']['tmp_name'])) {
+		if (is_uploaded_file($_FILES['backup_file']['tmp_name']) && file_exists($backup_path.'/'.$backup_file)) {
 			//move temp file to backup path
 			move_uploaded_file($_FILES['backup_file']['tmp_name'], $backup_path.'/'.$backup_file);
 			//determine file format and restore backup
```
