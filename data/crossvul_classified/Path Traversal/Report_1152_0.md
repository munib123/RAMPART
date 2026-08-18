# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 1152_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1152_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

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
	Copyright (C) 2008-2012
	All Rights Reserved.

	Contributor(s):
	Mark J Crane <markjcrane@fusionpbx.com>
*/

//includes
	include "root.php";
	require_once "resources/require.php";
	require_once "resources/check_auth.php";

//check permisions
	if (permission_exists('xml_cdr_delete')) {
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
-	Copyright (C) 2008-2012
+	Copyright (C) 2008-2019
 	All Rights Reserved.
 
 	Contributor(s):
@@ -45,26 +45,40 @@
 //get posted values, if any
 	if (sizeof($_REQUEST) > 0) {
 		$xml_cdr_uuids = $_REQUEST["id"];
-		$recording_file_path = $_REQUEST["rec"];
-
 		if (sizeof($xml_cdr_uuids) > 0) {
 			foreach ($xml_cdr_uuids as $index => $xml_cdr_uuid) {
-				// delete record from v_xml_cdr
-				$sql = "delete from v_xml_cdr ";
-				$sql .= "where xml_cdr_uuid = '".$xml_cdr_uuid."' ";
-				$prep_statement = $db->prepare(check_sql($sql));
-				$prep_statement->execute();
-				unset($sql, $prep_statement);
-				//delete recording from fs and v_call_recordings respectively, if any
-				if ($recording_file_path[$index] != '' ) {
+				if (is_uuid($xml_cdr_uuid)) {
+					// delete record from v_xml_cdr
+					$sql = "delete from v_xml_cdr ";
+					$sql .= "where xml_cdr_uuid = :xml_cdr_uuid ";
+					$parameters['xml_cdr_uuid'] = $xml_cdr_uuid;
+					$database = new database;
+					$database->execute($sql, $parameters);
+					unset($sql, $parameters);
+
+					//get the call recordings
+					$sql = "select * from v_call_recordings ";
+					$sql .= "where call_recording_uuid = :xml_cdr_uuid ";
+					$parameters['xml_cdr_uuid'] = $xml_cdr_uuid;
+					$database = new database;
+					$row = $database->select($sql, $parameters, 'row');
+					unset($sql, $parameters);
+
+					//delete the call recording
+					$call_recording_path = realpath($row['call_recording_path']);
+					$call_recording_name = $row['call_recording_name'];
+					if (file_exists($call_recording_path.'/'.$call_recording_name)) {
+						@unlink($call_recording_path.'/'.$call_recording_name);
+					}
+
+					//delete the call recording meta data
 					$sql = "delete from v_call_recordings ";
-					$sql .= "where call_recording_uuid = '".$xml_cdr_uuid."' ";
-					$prep_statement = $db->prepare(check_sql($sql));
-					$prep_statement->execute();
-					unset($sql, $prep_statement);
-					if (file_exists(base64_decode($recording_file_path[$index]))) {
-						@unlink(base64_decode($recording_file_path[$index]));
-					}
+					$sql .= "where call_recording_uuid = :xml_cdr_uuid ";
+					$parameters['xml_cdr_uuid'] = $xml_cdr_uuid;
+					$database = new database;
+					$database->execute($sql, $parameters);
+					unset($sql, $parameters);
+
 				}
 			}
 		}
@@ -72,6 +86,6 @@
 
 //set message and redirect the user
 	$_SESSION["message"] = $text['message-delete'].": ".sizeof($xml_cdr_uuids);
-	header("Location: xml_cdr.php".(($_SESSION['xml_cdr']['last_query'] != '') ? "?".$_SESSION['xml_cdr']['last_query'] : null));
+	header("Location: xml_cdr.php");
 
 ?>
```
