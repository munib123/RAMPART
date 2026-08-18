# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2773_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2773_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-32 of the vulnerable file.

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
	<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
	
	<title>Big-Red-Button Demo</title>
	<link type="text/css" rel="stylesheet" href="/lib/css/kmc.css" />
	<style>
		#main .content .title h1 { font-size: 24px; font-weight: bold; }
		#main p { margin-bottom: 20px; font-size: 18px; }
	</style>
	
	<script src="/lib/js/jquery-1.8.3.min.js"></script>
	<script type="text/javascript" src="/html5/html5lib/<?php echo $html5Version; ?>/mwEmbedLoader.php"></script>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,8 +8,8 @@
 if(!isset($_GET['playerVersion']))
 	die('html5 lib version must be supplied in query string');
 
-$partnerId = safeGetInput('partnerId', '/[^0-9]/');
-$html5Version = safeGetInput('playerVersion', '/[^v0-9.]/');
+$partnerId = safeGetInput('partnerId', INTEGER_ONLY_PATTERN);
+$html5Version = safeGetInput('playerVersion', HTML_VERSION_PATTERN);
 ?>
 <!DOCTYPE html>
 <!--[if lt IE 7]>      <html class="lt-ie10 lt-ie9 lt-ie8 lt-ie7"> <![endif]-->
@@ -307,15 +307,15 @@
 		</tr>
 		<tr>
 			<td>Admin Secret:</td>
-			<td><input type="text" id="txtSecret" value="<?php echo isset($_GET['secret']) ? safeGetInput('secret', '/[^A-Za-z0-9]/') : ''; ?>" />
+			<td><input type="text" id="txtSecret" value="<?php echo isset($_GET['secret']) ? safeGetInput('secret', SECRET_PATTERN) : ''; ?>" />
 		</td>
 		<tr>
 			<td>Entry Id:</td>
-			<td><input type="text" id="txtEntryId" value="<?php echo isset($_GET['entryId']) ? safeGetInput('entryId', '/[^a-z0-9_]/') : ''; ?>" />
+			<td><input type="text" id="txtEntryId" value="<?php echo isset($_GET['entryId']) ? safeGetInput('entryId', ENTRY_ID_PATTERN) : ''; ?>" />
 		</td>
 		<tr>
         	<td>uiConf Id:</td>
-            <td><input type="text" id="txtUiConfId" value="<?php echo isset($_GET['uiConfId']) ? safeGetInput('uiConfId', '/[^0-9]/') : ''; ?>" />
+            <td><input type="text" id="txtUiConfId" value="<?php echo isset($_GET['uiConfId']) ? safeGetInput('uiConfId', INTEGER_ONLY_PATTERN) : ''; ?>" />
 		</td>
 		<tr>
 			<td colspan="2">
```
