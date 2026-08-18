# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 377_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `377_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 93-133 of the vulnerable file.

			if (is_dir (getcwd () . $_POST['dir'])) {
				$ok++;
			}
		}
		
		if ($ok < 3) {
			echo __ ('Invalid directory');
			return;
		}
		
		if (! isset ($_POST['newName'])) {
			echo __ ('No name specified');
			break;
		}

		if (strpos ($_POST['newName'], '..') !== false || strpos ($_POST['newName'], '/') !== false) {
			echo __ ('Invalid name');
			return;
		}
		
		if (preg_match ('/\.(php|phtml|pht|php3|php4|php5|phar|js|rb|py|pl|sh|bash|exe)$/i', $_POST['newName'])) {
			echo __ ('Invalid file type');
			return;
		}
		
		$dest = ltrim ($_POST['dir'], '/') . '/' . $_POST['newName'];

		if (file_exists ($dest)) {
			echo __ ('File already exists');
			return;
		}

		if (! is_uploaded_file ($_FILES['handle']['tmp_name'])) {
			echo __ ('File upload failed');
			return;
		}

		if (! move_uploaded_file ($_FILES['handle']['tmp_name'], $dest)) {
			echo __ ('File save failed');
			return;
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -110,7 +110,9 @@
 			return;
 		}
 		
-		if (preg_match ('/\.(php|phtml|pht|php3|php4|php5|phar|js|rb|py|pl|sh|bash|exe)$/i', $_POST['newName'])) {
+		$_POST['newName'] = trim ($_POST['newName']);
+		
+		if (preg_match ('/\.(php|phtml|pht|php3|php4|php5|phar|js|rb|py|pl|sh|bash|exe|htaccess|htpasswd)$/i', $_POST['newName'])) {
 			echo __ ('Invalid file type');
 			return;
 		}
```
