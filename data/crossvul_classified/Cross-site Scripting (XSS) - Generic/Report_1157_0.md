# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1157_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1157_0`)

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
	James Rose <james.o.rose@gmail.com>
*/
include "root.php";
require_once "resources/require.php";
require_once "resources/check_auth.php";
if (permission_exists('conference_interactive_view')) {
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
@@ -17,23 +17,27 @@
 
 	The Initial Developer of the Original Code is
 	Mark J Crane <markjcrane@fusionpbx.com>
-	Portions created by the Initial Developer are Copyright (C) 2008-2012
+	Portions created by the Initial Developer are Copyright (C) 2008-2019
 	the Initial Developer. All Rights Reserved.
 
 	Contributor(s):
 	Mark J Crane <markjcrane@fusionpbx.com>
 	James Rose <james.o.rose@gmail.com>
 */
-include "root.php";
-require_once "resources/require.php";
-require_once "resources/check_auth.php";
-if (permission_exists('conference_interactive_view')) {
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
+	if (permission_exists('conference_interactive_view')) {
+		//access granted
+	}
+	else {
+		echo "access denied";
+		exit;
+	}
 
 //add multi-lingual support
 	$language = new text;
@@ -83,7 +87,7 @@
 }
 
 var requestTime = function() {
-	var url = 'conference_interactive_inc.php?c=<?php echo trim($_REQUEST["c"]); ?>';
+	var url = 'conference_interactive_inc.php?c=<?php echo trim(escape($_REQUEST["c"])); ?>';
 	new loadXmlHttp(url, 'ajax_reponse');
 	setInterval(function(){new loadXmlHttp(url, 'ajax_reponse');}, 1222);
 }
```
