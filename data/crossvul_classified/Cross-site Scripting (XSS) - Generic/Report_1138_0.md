# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1138_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1138_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 24-64 of the vulnerable file.

	Mark J Crane <markjcrane@fusionpbx.com>
*/

//includes
	require_once "root.php";
	require_once "resources/require.php";
	require_once "resources/check_auth.php";

//check permissions
	if (!permission_exists('message_view')) {
		echo "access denied";
		exit;
	}

//add multi-lingual support
	$language = new text;
	$text = $language->get();

//get number of messages to load
	$number = preg_replace('{[\D]}', '', $_GET['number']);
	$contact_uuid = $_GET['contact_uuid'];

//set refresh flag
	$refresh = $_GET['refresh'] == 'true' ? true : false;

//get messages
	if (isset($_SESSION['message']['display_last']['text']) && $_SESSION['message']['display_last']['text'] != '') {
		$array = explode(' ',$_SESSION['message']['display_last']['text']);
		if (is_array($array) && is_numeric($array[0]) && $array[0] > 0) {
			if ($array[1] == 'messages') {
				$limit = limit_offset($array[0], 0);
			}
			else {
				$since = "and message_date >= :message_date ";
				$parameters['message_date'] = date("Y-m-d H:i:s", strtotime('-'.$_SESSION['message']['display_last']['text']));
			}
		}
	}
	if ($limit == '' && $since == '') { $limit = limit_offset(25, 0); } //default (message count)
	$sql = "select ";
	$sql .= "message_uuid, ";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,7 +41,7 @@
 
 //get number of messages to load
 	$number = preg_replace('{[\D]}', '', $_GET['number']);
-	$contact_uuid = $_GET['contact_uuid'];
+	$contact_uuid = (is_uuid($_GET['contact_uuid'])) ? $_GET['contact_uuid'] : null;
 
 //set refresh flag
 	$refresh = $_GET['refresh'] == 'true' ? true : false;
```
