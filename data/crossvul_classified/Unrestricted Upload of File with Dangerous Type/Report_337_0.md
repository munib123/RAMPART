# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 337_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `337_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 29-70 of the vulnerable file.


// Settings
// $targetDir = ini_get("upload_tmp_dir") . DIRECTORY_SEPARATOR . "plupload";
	$targetDir = e_IMPORT;
//$targetDir = 'uploads';

	$cleanupTargetDir = true; // Remove old files
	$maxFileAge = 5 * 3600; // Temp file age in seconds

// 5 minutes execution time
	@set_time_limit(5 * 60);

// Uncomment this one to fake upload time
// usleep(5000);

// Get parameters
	$chunk = isset($_REQUEST["chunk"]) ? intval($_REQUEST["chunk"]) : 0;
	$chunks = isset($_REQUEST["chunks"]) ? intval($_REQUEST["chunks"]) : 0;
	$fileName = isset($_REQUEST["name"]) ? $_REQUEST["name"] : '';



// Clean the fileName for security reasons
	$fileName = preg_replace('/[^\w\._]+/', '_', $fileName);

	$fileName= 'hello.jpg';

	if(!empty($_FILES['file']['name'])) // dropzone support v2.1.9
	{
		$fileName = $_FILES['file']['name'];
	}

// Make sure the fileName is unique but only if chunking is disabled
	if($chunks < 2 && file_exists($targetDir . DIRECTORY_SEPARATOR . $fileName))
	{
		$ext = strrpos($fileName, '.');
		$fileName_a = substr($fileName, 0, $ext);
		$fileName_b = substr($fileName, $ext);

		$count = 1;
		while(file_exists($targetDir . DIRECTORY_SEPARATOR . $fileName_a . '_' . $count . $fileName_b))
		{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,12 +46,8 @@
 	$chunks = isset($_REQUEST["chunks"]) ? intval($_REQUEST["chunks"]) : 0;
 	$fileName = isset($_REQUEST["name"]) ? $_REQUEST["name"] : '';
 
-
-
 // Clean the fileName for security reasons
 	$fileName = preg_replace('/[^\w\._]+/', '_', $fileName);
-
-	$fileName= 'hello.jpg';
 
 	if(!empty($_FILES['file']['name'])) // dropzone support v2.1.9
 	{
@@ -195,6 +191,14 @@
 
 	$filePath = str_replace('//','/',$filePath); // cleanup .
 
+
+	if(e107::getFile()->isClean($filePath) !== true)
+	{
+		@unlink($filePath);
+		die('{"jsonrpc" : "2.0", "error" : {"code": 103, "message": "Bad File Detected."}, "id" : "id"}');
+	}
+
+
 	$convertToJpeg = e107::getPref('convert_to_jpeg', 0);
 	$fileSize = filesize($filePath);
 
@@ -208,6 +212,9 @@
 		}
 
 	}
+
+
+
 
 	if($_GET['for'] != '') // leave in upload directory if no category given.
 	{
```
