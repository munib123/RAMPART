# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 877_5
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `877_5`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 1-39 of the vulnerable file.

<?php defined('BLUDIT') or die('Bludit CMS.');
header('Content-Type: application/json');

// $_POST
// ----------------------------------------------------------------------------
// (string) $_POST['username']
$username = empty($_POST['username']) ? false : $_POST['username'];
// ----------------------------------------------------------------------------

if ($username===false) {
	ajaxResponse(1, 'Error in username.');
}

if (!isset($_FILES['profilePictureInputFile'])) {
	ajaxResponse(1, 'Error trying to upload the profile picture.');
}

// File extension
$fileExtension 	= pathinfo($_FILES['profilePictureInputFile']['name'], PATHINFO_EXTENSION);
// Tmp filename
$tmpFilename = $username.'.'.$fileExtension;
// Final filename
$filename = $username.'.png';

// Move from temporary directory to uploads folder
rename($_FILES['profilePictureInputFile']['tmp_name'], PATH_TMP.$tmpFilename);

// Resize and convert to png
$image = new Image();
$image->setImage(PATH_TMP.$tmpFilename, PROFILE_IMG_WIDTH, PROFILE_IMG_HEIGHT, 'crop');
$image->saveImage(PATH_UPLOADS_PROFILES.$filename, PROFILE_IMG_QUALITY, false, true);

// Remove the tmp file
unlink(PATH_TMP.$tmpFilename);

// Permissions
chmod(PATH_UPLOADS_PROFILES.$filename, 0644);

ajaxResponse(0, 'Image uploaded.', array(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,11 +16,26 @@
 }
 
 // File extension
-$fileExtension 	= pathinfo($_FILES['profilePictureInputFile']['name'], PATHINFO_EXTENSION);
+$allowedExtensions = array('gif', 'png', 'jpg', 'jpeg', 'svg');
+$fileExtension = pathinfo($_FILES['profilePictureInputFile']['name'], PATHINFO_EXTENSION);
+if (!in_array($fileExtension, $allowedExtensions) ) {
+	$message = 'File type is not supported. Allowed types: '.implode(', ',$allowedExtensions);
+	Log::set($message, LOG_TYPE_ERROR);
+	ajaxResponse(1, $message);
+}
+
 // Tmp filename
 $tmpFilename = $username.'.'.$fileExtension;
+
 // Final filename
 $filename = $username.'.png';
+
+// Check path traversal
+if (Text::stringContains($username, '/', false)) {
+	$message = 'Path traversal detected.';
+	Log::set($message, LOG_TYPE_ERROR);
+	ajaxResponse(1, $message);
+}
 
 // Move from temporary directory to uploads folder
 rename($_FILES['profilePictureInputFile']['tmp_name'], PATH_TMP.$tmpFilename);
```
