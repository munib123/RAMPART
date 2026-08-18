# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1151_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1151_0`)

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
	Portions created by the Initial Developer are Copyright (C) 2008-2016
	the Initial Developer. All Rights Reserved.

	Contributor(s):
	Mark J Crane <markjcrane@fusionpbx.com>
*/

//includes
	include "root.php";
	require_once "resources/require.php";
	require_once "resources/check_auth.php";

//check permissions
	if (permission_exists('recording_play')) {
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
-	Portions created by the Initial Developer are Copyright (C) 2008-2016
+	Portions created by the Initial Developer are Copyright (C) 2008-2019
 	the Initial Developer. All Rights Reserved.
 
 	Contributor(s):
@@ -37,7 +37,8 @@
 		echo "access denied";
 		exit;
 	}
-	
+
+//get the variables
 	$filename = $_GET['filename'];
 	$type = $_GET['type']; //moh //rec
 
@@ -51,7 +52,7 @@
 <table width="100%" border="0" cellpadding="0" cellspacing="0">
 	<tr>
 		<td align='center'>
-			<b>file: <?php echo $filename ?></b>
+			<b><?php echo escape($filename) ?></b>
 		</td>
 	</tr>
 	<tr>
@@ -69,7 +70,7 @@
 			}
 			else {
 				echo "<audio src=\"http://localhost:8000/mod/recordings/recordings.php?a=download&type=".urlencode($type)."&filename=".urlencode($filename)."\" autoplay=\"autoplay\"></audio>";
-				echo "<embed src=\"recordings.php?a=download&type=".urlencode($type)."&filename=".urlencode($filename)."\" autostart=\"true\" width=\"300\" height=\"90\" name=\"sound_".$filename."\" enablejavascript=\"true\">\n";
+				echo "<embed src=\"recordings.php?a=download&type=".urlencode($type)."&filename=".urlencode($filename)."\" autostart=\"true\" width=\"300\" height=\"90\" name=\"sound_".escape($filename)."\" enablejavascript=\"true\">\n";
 			}
 		}
 		if ($file_ext == "mp3") {
```
