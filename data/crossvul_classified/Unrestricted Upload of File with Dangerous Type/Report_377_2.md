# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 377_2
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `377_2`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 32-72 of the vulnerable file.


foreach ($_FILES['file']['error'] as $error) {
	if ($error > 0) {
		$errors = array (
			1 => __ ('File size is too large.'),
			2 => __ ('File size is too large.'),
			3 => __ ('The file was only partially uploaded.'),
			4 => __ ('No file was uploaded.'),
			6 => __ ('Missing a temporary folder, check your PHP setup.'),
			7 => __ ('Failed to write the file to disk.'),
			8 => __ ('A PHP extension stopped the file upload.')
		);
		$page->title = __ ('An Error Occurred');
		echo '<p>' . __ ('Error message') . ': ' . $errors[$error] . '</p>';
		echo '<p><a href="/filemanager">' . __ ('Back') . '</a></p>';
		return;
	}
}

for ($i = 0; $i < count ($_FILES['file']['name']); $i++) {
	$_FILES['file']['name'][$i] = urldecode ($_FILES['file']['name'][$i]);
	if (@file_exists ($root . $_POST['path'] . '/' . $_FILES['file']['name'][$i])) {
		$page->title = __ ('File Already Exists') . ': ' . $_FILES['file']['name'][$i];
		echo '<p>' . __ ('A file by that name already exists.') . '</p>';
		echo '<p><a href="/filemanager">' . __ ('Back') . '</a></p>';
		return;
	}
	if (strpos ($_FILES['file']['name'][$i], '..') !== false) {
		$page->title = __ ('Invalid File Name') . ': ' . $_FILES['file']['name'][$i];
		echo '<p>' . __ ('The file name contains invalid characters.') . '</p>';
		echo '<p><a href="/filemanager">' . __ ('Back') . '</a></p>';
		return;
	}
	if (preg_match ('/\.(php|phtml|pht|php3|php4|php5|phar|js|rb|py|pl|sh|bash|exe)$/i', $_FILES['file']['name'][$i])) {
		$page->title = __ ('Invalid File Name') . ': ' . $_FILES['file']['name'][$i];
		echo '<p>' . __ ('Cannot upload executable files due to security.') . '</p>';
		echo '<p><a href="/filemanager">' . __ ('Back') . '</a></p>';
		return;
	}
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,7 +49,7 @@
 }
 
 for ($i = 0; $i < count ($_FILES['file']['name']); $i++) {
-	$_FILES['file']['name'][$i] = urldecode ($_FILES['file']['name'][$i]);
+	$_FILES['file']['name'][$i] = trim (urldecode ($_FILES['file']['name'][$i]));
 	if (@file_exists ($root . $_POST['path'] . '/' . $_FILES['file']['name'][$i])) {
 		$page->title = __ ('File Already Exists') . ': ' . $_FILES['file']['name'][$i];
 		echo '<p>' . __ ('A file by that name already exists.') . '</p>';
@@ -62,7 +62,7 @@
 		echo '<p><a href="/filemanager">' . __ ('Back') . '</a></p>';
 		return;
 	}
-	if (preg_match ('/\.(php|phtml|pht|php3|php4|php5|phar|js|rb|py|pl|sh|bash|exe)$/i', $_FILES['file']['name'][$i])) {
+	if (preg_match ('/\.(php|phtml|pht|php3|php4|php5|phar|js|rb|py|pl|sh|bash|exe|htaccess|htpasswd)$/i', $_FILES['file']['name'][$i])) {
 		$page->title = __ ('Invalid File Name') . ': ' . $_FILES['file']['name'][$i];
 		echo '<p>' . __ ('Cannot upload executable files due to security.') . '</p>';
 		echo '<p><a href="/filemanager">' . __ ('Back') . '</a></p>';
```
