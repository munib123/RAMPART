# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2773_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2773_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-31 of the vulnerable file.

<?php
require_once (dirname(__FILE__) . '/safeGetInput.php');

if(!isset($_GET['partnerId']))
	die('partnerId must be supplied in query string');
	
if(!isset($_GET['playerVersion']))
	die('html5 lib version must be supplied in query string');

$partnerId = safeGetInput('partnerId', '/[^0-9]/');
$html5Version = safeGetInput('playerVersion', '/[^v0-9.]/');

?>
<!DOCTYPE html>
<!--[if lt IE 7]>      <html class="lt-ie10 lt-ie9 lt-ie8 lt-ie7"> <![endif]-->
<!--[if IE 7]>         <html class="lt-ie10 lt-ie9 lt-ie8"> <![endif]-->
<!--[if IE 8]>         <html class="lt-ie10 lt-ie9"> <![endif]-->
<!--[if lt IE 10]>     <html class="lt-ie10"> <![endif]-->
<!--[if gt IE 8]><!--> <html> <!--<![endif]-->
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <title>Kaltura</title>

    <!-- Bootstrap -->
    <link href="css/main.css" rel="stylesheet">	
	<link href='https://fonts.googleapis.com/css?family=Lato:400,700,300' rel='stylesheet' type='text/css'>
	
	<script src="/lib/js/jquery-1.8.3.min.js"></script>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,8 +7,8 @@
 if(!isset($_GET['playerVersion']))
 	die('html5 lib version must be supplied in query string');
 
-$partnerId = safeGetInput('partnerId', '/[^0-9]/');
-$html5Version = safeGetInput('playerVersion', '/[^v0-9.]/');
+$partnerId = safeGetInput('partnerId', INTEGER_ONLY_PATTERN);
+$html5Version = safeGetInput('playerVersion', HTML_VERSION_PATTERN);
 
 ?>
 <!DOCTYPE html>
@@ -212,19 +212,19 @@
 	  	<table>
 		<tr style="display: none; ">
 			<td>Admin Secret:</td>
-			<td><input type="text" id="txtSecret" value="<?php echo isset($_GET['secret']) ? safeGetInput('secret', '/[^A-Za-z0-9]/') : ''; ?>" />
+			<td><input type="text" id="txtSecret" value="<?php echo isset($_GET['secret']) ? safeGetInput('secret', SECRET_PATTERN) : ''; ?>" />
 		</td>
 		<tr style="display: none; ">
 			<td>Entry Id:</td>
-			<td><input type="text" id="txtEntryId" value="<?php echo isset($_GET['entryId']) ? safeGetInput('entryId', '/[^a-z0-9_]/') : ''; ?>" />
+			<td><input type="text" id="txtEntryId" value="<?php echo isset($_GET['entryId']) ? safeGetInput('entryId', ENTRY_ID_PATTERN) : ''; ?>" />
 		</td>
 		<tr style="display: none; ">
         	<td>Admin uiConf Id:</td>
-            <td><input type="text" id="txtAdminUiConfId" value="<?php echo isset($_GET['adminUiConfId']) ? safeGetInput('adminUiConfId', '/[^0-9]/') : ''; ?>" />
+            <td><input type="text" id="txtAdminUiConfId" value="<?php echo isset($_GET['adminUiConfId']) ? safeGetInput('adminUiConfId', INTEGER_ONLY_PATTERN) : ''; ?>" />
 		</td>
 		<tr style="display: none; ">
         	<td>User uiConf Id:</td>
-            <td><input type="text" id="txtUiConfId" value="<?php echo isset($_GET['uiConfId']) ? safeGetInput('uiConfId', '/[^0-9]/') : ''; ?>" />
+            <td><input type="text" id="txtUiConfId" value="<?php echo isset($_GET['uiConfId']) ? safeGetInput('uiConfId', INTEGER_ONLY_PATTERN) : ''; ?>" />
 		</td>
 		<tr style="display: none; ">
 			<td colspan="2">
```
