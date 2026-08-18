# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 409_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `409_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 31-71 of the vulnerable file.


	$folder = isset($_POST["folder"]) ? sqlescape($_POST["folder"]) : false;
	$errors = array();
	$successes = 0;

	// This is an iFrame, so we're going to call the parent from it.
	echo '<html><body><script>';

	// If the user doesn't have permission to upload to this folder, throw an error.
	$perm = $admin->getResourceFolderPermission($folder);
	if ($perm != "p") {
		echo 'parent.BigTreeFileManager.uploadError("You do not have permission to upload to this folder.");';
	} else {
		foreach ($_FILES["files"]["tmp_name"] as $number => $temp_name) {
			$error = $_FILES["files"]["error"][$number];
			$file_name = $replacing ? $replacing : $_FILES["files"]["name"][$number];

			// Throw a growl error
			if ($error) {
				$file_name = htmlspecialchars($file_name);
				if ($error == 2 || $error == 1) {
					$errors[] = $file_name." was too large ".BigTree::formatBytes(BigTree::uploadMaxFileSize())." max)";
				} else {
					$errors[] = "Uploading $file_name failed (unknown error)";
				}
			// File successfully uploaded
			} elseif ($temp_name) {
				// See if this file already exists
				if ($replacing || !$admin->matchResourceMD5($temp_name,$_POST["folder"])) {
					$md5 = md5_file($temp_name);
		
					// Get the name and file extension
					$n = strrev($file_name);
					$extension = strtolower(strrev(substr($n,0,strpos($n,"."))));
		
					// See if it's an image
					list($iwidth,$iheight,$itype,$iattr) = getimagesize($temp_name);
		
					// It's a regular file
					if ($itype != IMAGETYPE_GIF && $itype != IMAGETYPE_JPEG && $itype != IMAGETYPE_PNG) {
						$type = "file";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,6 +48,7 @@
 			// Throw a growl error
 			if ($error) {
 				$file_name = htmlspecialchars($file_name);
+				
 				if ($error == 2 || $error == 1) {
 					$errors[] = $file_name." was too large ".BigTree::formatBytes(BigTree::uploadMaxFileSize())." max)";
 				} else {
@@ -79,9 +80,9 @@
 						// If we failed, either cloud storage upload failed, directory permissions are bad, or the file type isn't permitted
 						if (!$file) {
 							if ($storage->DisabledFileError) {
-								$errors[] = "$file_name has a disallowed extension: $extension.";
+								$errors[] = htmlspecialchars($file_name)." has a disallowed extension: $extension.";
 							} else {
-								$errors[] = "Uploading $file_name failed (unknown error).";
+								$errors[] = "Uploading ".htmlspecialchars($file_name)." failed (unknown error).";
 							}
 						// Otherwise make the database entry for the file we uplaoded.
 						} else {
@@ -138,7 +139,7 @@
 							}
 						} else {
 							$last_error = array_pop($bigtree["errors"]);
-							$errors[] = $last_error["error"];
+							$errors[] = BigTree::safeEncode($last_error["error"]);
 						}
 					}
 				}
```
