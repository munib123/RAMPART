# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1289_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1289_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 42-83 of the vulnerable file.

	$language = new text;
	$text = $language->get();

//send the header
	require_once "resources/header.php";

//javascript to toggle input/select boxes
	echo "<script type='text/javascript'>";
	echo "	function toggle(field) {";
	echo "		if (field == 'source') {";
	echo "			document.getElementById('caller_extension_uuid').selectedIndex = 0;";
	echo "			document.getElementById('caller_id_number').value = '';";
	echo "			$('#caller_extension_uuid').toggle();";
	echo "			$('#caller_id_number').toggle();";
	echo "			if ($('#caller_id_number').is(':visible')) { $('#caller_id_number').trigger('focus'); } else { $('#caller_extension_uuid').trigger('focus'); }";
	echo "		}";
	echo "	}";
	echo "</script>";

//start the html form
	if (strlen(check_str($_GET['redirect'])) > 0) {
		echo "<form method='get' action='" . $_GET['redirect'] . ".php'>\n";
	}
	else {
		echo "<form method='get' action='xml_cdr.php'>\n";
	}
	
	echo "<table width='100%' cellpadding='0' cellspacing='0'>\n";
	echo "	<tr>\n";
	echo "		<td width='30%' nowrap='nowrap' valign='top'><b>Advanced Search</b></td>\n";
	echo "		<td width='70%' align='right' valign='top'>";
	echo "			<input type='button' class='btn' name='' alt='back' onclick=\"window.location='xml_cdr.php'\" value='Back'>";
	echo "			<input type='submit' name='submit' class='btn' value='Search'>";
	echo "			<br /><br />";
	echo "		</td>\n";
	echo "	</tr>\n";
	echo "</table>\n";
	
	echo "<table cellpadding='0' cellspacing='0' border='0' width='100%'>\n";
	echo "	<tr>\n";
	echo "		<td width='50%' style='vertical-align: top;'>\n";
	
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -59,8 +59,8 @@
 	echo "</script>";
 
 //start the html form
-	if (strlen(check_str($_GET['redirect'])) > 0) {
-		echo "<form method='get' action='" . $_GET['redirect'] . ".php'>\n";
+	if ($_GET['redirect'] == 'xml_cdr_statistics') {
+		echo "<form method='get' action='xml_cdr_statistics.php'>\n";
 	}
 	else {
 		echo "<form method='get' action='xml_cdr.php'>\n";
```
