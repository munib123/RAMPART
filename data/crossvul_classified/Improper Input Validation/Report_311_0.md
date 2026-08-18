# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 311_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `311_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 20-60 of the vulnerable file.


if (! isset ($_FILES['file'])) {
	echo json_encode (array ('success' => false, 'error' => __ ('No file uploaded or file too large.')));
	return;
}

if (isset ($_FILES['file']['error']) && $_FILES['file']['error'] > 0) {
	$errors = array (
		1 => __ ('File size is too large.'),
		2 => __ ('File size is too large.'),
		3 => __ ('The file was only partially uploaded.'),
		4 => __ ('No file was uploaded.'),
		6 => __ ('Missing a temporary folder, check your PHP setup.'),
		7 => __ ('Failed to write the file to disk.'),
		8 => __ ('A PHP extension stopped the file upload.')
	);
	echo json_encode (array ('success' => false, 'error' => $errors[$_FILES['file']['error']]));
	return;
}

if (preg_match ('/\.(php5?|phtml|js|rb|py|pl|sh|bash|exe)$/i', $_FILES['file']['name'])) {
	echo json_encode (array ('success' => false, 'error' => __ ('Cannot upload executable files due to security.')));
	return;
}

// some browsers may urlencode the file name
$_FILES['file']['name'] = urldecode ($_FILES['file']['name']);

if (@file_exists ($root . $_POST['path'] . '/' . $_FILES['file']['name'])) {
	echo json_encode (array ('success' => false, 'error' => __ ('A file by that name already exists.')));
	return;
}
if (strpos ($_FILES['file']['name'], '..') !== false) {
	echo json_encode (array ('success' => false, 'error' => __ ('The file name contains invalid characters.')));
	return;
}

if (@move_uploaded_file ($_FILES['file']['tmp_name'], $root . $_POST['path'] . '/' . $_FILES['file']['name'])) {
	@chmod ($root . $_POST['path'] . '/' . $_FILES['file']['name'], 0666);
	$this->hook ('filemanager/add', array (
		'file' => $_POST['path'] . '/' . $_FILES['file']['name']
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,13 +37,13 @@
 	return;
 }
 
+// some browsers may urlencode the file name
+$_FILES['file']['name'] = urldecode ($_FILES['file']['name']);
+
 if (preg_match ('/\.(php5?|phtml|js|rb|py|pl|sh|bash|exe)$/i', $_FILES['file']['name'])) {
 	echo json_encode (array ('success' => false, 'error' => __ ('Cannot upload executable files due to security.')));
 	return;
 }
-
-// some browsers may urlencode the file name
-$_FILES['file']['name'] = urldecode ($_FILES['file']['name']);
 
 if (@file_exists ($root . $_POST['path'] . '/' . $_FILES['file']['name'])) {
 	echo json_encode (array ('success' => false, 'error' => __ ('A file by that name already exists.')));
```
