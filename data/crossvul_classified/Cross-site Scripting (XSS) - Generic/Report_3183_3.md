# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3183_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3183_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-28 of the vulnerable file.

<?php 
if(!isset($_GET['partnerId']))
	die('partnerId must be supplied in query string');
	
if(!isset($_GET['playerVersion']))
	die('html5 lib version must be supplied in query string');

$partnerId = $_GET['partnerId'];

$html5Version = $_GET['playerVersion'];
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
	
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,9 +5,9 @@
 if(!isset($_GET['playerVersion']))
 	die('html5 lib version must be supplied in query string');
 
-$partnerId = $_GET['partnerId'];
-
-$html5Version = $_GET['playerVersion'];
+$partnerId = strip_tags($_GET['partnerId']);
+
+$html5Version = strip_tags($_GET['playerVersion']);
 ?>
 <!DOCTYPE html>
 <!--[if lt IE 7]>      <html class="lt-ie10 lt-ie9 lt-ie8 lt-ie7"> <![endif]-->
@@ -305,15 +305,15 @@
 		</tr>
 		<tr>
 			<td>Admin Secret:</td>
-			<td><input type="text" id="txtSecret" value="<?php echo isset($_GET['secret']) ? $_GET['secret'] : ''; ?>" />
+			<td><input type="text" id="txtSecret" value="<?php echo isset($_GET['secret']) ? strip_tags($_GET['secret']) : ''; ?>" />
 		</td>
 		<tr>
 			<td>Entry Id:</td>
-			<td><input type="text" id="txtEntryId" value="<?php echo isset($_GET['entryId']) ? $_GET['entryId'] : ''; ?>" />
+			<td><input type="text" id="txtEntryId" value="<?php echo isset($_GET['entryId']) ? strip_tags($_GET['entryId']) : ''; ?>" />
 		</td>
 		<tr>
         	<td>uiConf Id:</td>
-            <td><input type="text" id="txtUiConfId" value="<?php echo isset($_GET['uiConfId']) ? $_GET['uiConfId'] : ''; ?>" />
+            <td><input type="text" id="txtUiConfId" value="<?php echo isset($_GET['uiConfId']) ? strip_tags($_GET['uiConfId']) : ''; ?>" />
 		</td>
 		<tr>
 			<td colspan="2">
```
