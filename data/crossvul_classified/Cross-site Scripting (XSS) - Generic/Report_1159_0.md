# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1159_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1159_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 64-104 of the vulnerable file.


		//redirect the browser
		header("Location: fileoptions.php");
	}
	else {
		//create the token
		$key_name = '/app/edit/file_delete';
		$_SESSION['keys'][$key_name] = bin2hex(random_bytes(32));
		$_SESSION['token'] = hash_hmac('sha256', $key_name, $_SESSION['keys'][$key_name]);

		//display form
		require_once "header.php";
		echo "<br>";
		echo "<div align='left'>";
		echo "	<form method='POST' action=''>";
		echo "		<table>";
		echo "			<tr>";
		echo "				<td>".$text['label-path']."</td>";
		echo "			</tr>";
		echo "			<tr>";
		echo "				<td>".$folder."</td>";
		echo "			</tr>";
		echo "		</table>";
		echo "		<br />";
		echo "		<table>";
		echo "			<tr>";
		echo "				<td>".$text['label-file-name']."</td>";
		echo "			</tr>";
		echo "			<tr>";
		echo "				<td><input type='text' name='file' value='".$file."'></td>";
		echo "			</tr>";
		echo "			<tr>";
		echo "				<td colspan='1' align='right'>";
		echo "					<input type='hidden' name='folder' value='$folder'>";
		echo "					<input type='hidden' name='token' id='token' value='". $_SESSION['token']. "'>";
		echo "					<input type='submit' value='".$text['button-del-file']."'>";
		echo "				</td>";
		echo "			</tr>";
		echo "		</table>";
		echo "	</form>";
		echo "</div>";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -81,7 +81,7 @@
 		echo "				<td>".$text['label-path']."</td>";
 		echo "			</tr>";
 		echo "			<tr>";
-		echo "				<td>".$folder."</td>";
+		echo "				<td>".escape($folder)."</td>";
 		echo "			</tr>";
 		echo "		</table>";
 		echo "		<br />";
@@ -90,11 +90,11 @@
 		echo "				<td>".$text['label-file-name']."</td>";
 		echo "			</tr>";
 		echo "			<tr>";
-		echo "				<td><input type='text' name='file' value='".$file."'></td>";
+		echo "				<td><input type='text' name='file' value='".escape($file)."'></td>";
 		echo "			</tr>";
 		echo "			<tr>";
 		echo "				<td colspan='1' align='right'>";
-		echo "					<input type='hidden' name='folder' value='$folder'>";
+		echo "					<input type='hidden' name='folder' value='".escape($folder)."'>";
 		echo "					<input type='hidden' name='token' id='token' value='". $_SESSION['token']. "'>";
 		echo "					<input type='submit' value='".$text['button-del-file']."'>";
 		echo "				</td>";
@@ -106,5 +106,4 @@
 		//include the footer
 		require_once "footer.php";
 	}
-
 ?>
```
