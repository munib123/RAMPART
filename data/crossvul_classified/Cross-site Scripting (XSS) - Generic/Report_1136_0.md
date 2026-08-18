# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1136_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1136_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 6-55 of the vulnerable file.

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
	Copyright (C) 2010
	All Rights Reserved.

	Contributor(s):
	Mark J Crane <markjcrane@fusionpbx.com>
*/
include "root.php";
require_once "resources/require.php";
require_once "resources/check_auth.php";
if (permission_exists('active_queue_view')) {
	//access granted
}
else {
	echo "access denied";
	exit;
}

//add multi-lingual support
	$language = new text;
	$text = $language->get();

//get the fifo_name from http and set it to a php variable
	$fifo_name = trim($_REQUEST["c"]);

//if not the user is not a member of the superadmin then restrict to viewing their own domain
	if (!if_group("superadmin")) {
		if (stripos($fifo_name, $_SESSION['domain_name']) === false) {
			echo "access denied";
			exit;
		}
	}

//remove the domain from fifo name
	$tmp_fifo_name = str_replace('_', ' ', $fifo_name);
	$tmp_fifo_array = explode('@', $tmp_fifo_name);
	$tmp_fifo_name = $tmp_fifo_array[0];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,23 +23,27 @@
 	Contributor(s):
 	Mark J Crane <markjcrane@fusionpbx.com>
 */
-include "root.php";
-require_once "resources/require.php";
-require_once "resources/check_auth.php";
-if (permission_exists('active_queue_view')) {
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
+//check permissions
+	if (permission_exists('active_queue_view')) {
+		//access granted
+	}
+	else {
+		echo "access denied";
+		exit;
+	}
 
 //add multi-lingual support
 	$language = new text;
 	$text = $language->get();
 
 //get the fifo_name from http and set it to a php variable
-	$fifo_name = trim($_REQUEST["c"]);
+	$fifo_name = preg_replace('#[^a-zA-Z0-9\_\@\-./]#', '', $_REQUEST["c"]);
 
 //if not the user is not a member of the superadmin then restrict to viewing their own domain
 	if (!if_group("superadmin")) {
@@ -139,4 +143,5 @@
 echo "<br><br>";
 
 require_once "resources/footer.php";
+
 ?>
```
