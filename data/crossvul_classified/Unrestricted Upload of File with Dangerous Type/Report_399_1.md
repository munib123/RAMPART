# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 399_1
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `399_1`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 66-106 of the vulnerable file.

				@unlink($filePath);
		}
		closedir($dir);
	}
}

// HTTP headers for no cache etc
/*
header('Content-type: text/plain; charset=UTF-8');
header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");
header("Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT");
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
*/

// Settings
$targetDir = NAVIGATE_PRIVATE.'/'.$website->id.'/files';
$maxFileAge = 24 * 60 * 60; // Temp file age in seconds (1 day)

// no maximum uploading / execution time
@set_time_limit(0);

//file_put_contents(NAVIGATE_PRIVATE.'/'.$website->id.'/files/out.txt', print_r($_FILES, true));

// filedrop drag'n'drop engine	
if($_REQUEST['engine']=='dropzone')
{
	if($user->permission("files.upload")=="true")
	{
		$tmpfilename = tempnam($targetDir, "upload-");
		$tmpfilename = basename($tmpfilename);

		if(count($_FILES) > 0)
		{
			if(!file_exists($_FILES['upload']['tmp_name']))
				die('{"jsonrpc" : "2.0", "error" : {"code": 100, "message": "Uploaded file missing."}, "id" : "id"}');

			if(empty($_SERVER['HTTP_ACCEPT_CHARSET']))
				$_SERVER['HTTP_ACCEPT_CHARSET'] = 'UTF-8';

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -83,10 +83,8 @@
 $targetDir = NAVIGATE_PRIVATE.'/'.$website->id.'/files';
 $maxFileAge = 24 * 60 * 60; // Temp file age in seconds (1 day)
 
-// no maximum uploading / execution time
+// no maximum uploading/execution time
 @set_time_limit(0);
-
-//file_put_contents(NAVIGATE_PRIVATE.'/'.$website->id.'/files/out.txt', print_r($_FILES, true));
 
 // filedrop drag'n'drop engine	
 if($_REQUEST['engine']=='dropzone')
@@ -135,27 +133,6 @@
 			core_terminate();
 		}
 	}
-}
-else if($_REQUEST['engine']=='picnik')
-{
-	// PHP script to receive image data from Picnik via HTTP POST
-	// retrieve the image's attributes from the $_FILES array
-	$image_tmp_filename = $_FILES['file']['tmp_name'];
-	$image_filename = $_FILES['file']['name'];
-	
-	// Save the image to disk.  It'll go into the same directory as
-	// this script.  You'd probably want to put it somewhere else in the
-	// file system like a "/images" directory, or maybe even into a database.
-	// Make sure your web server has write access to the destination dir,
-	// or the call to file_put_contents isn't going to work.
-	$image_data = file_get_contents( $image_tmp_filename );
-	
-	if(!empty($_REQUEST['id']) && file_exists($targetDir.'/'.$_REQUEST['id']))
-	{	
-		file_put_contents( $targetDir.'/'.$_REQUEST['id'], $image_data );
-	}
-	
-	core_terminate();
 }
 else if($_REQUEST['engine']=='pixlr')
 {	
```
