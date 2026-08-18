# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 5583_6
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5583_6`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 56-96 of the vulnerable file.

	edit_file($current_dir, $GLOBALS["item"]);
break;
//------------------------------------------------------------------------------
// DELETE FILE(S)/DIR(S)
case "delete":
	require "./_include/fun_del.php";
	del_items($current_dir);
break;
//------------------------------------------------------------------------------
// COPY/MOVE FILE(S)/DIR(S)
case "copy":	case "move":
	require "./_include/fun_copy_move.php";
	copy_move_items($current_dir);
break;
//------------------------------------------------------------------------------
// DOWNLOAD FILE
case "download":
	ob_start(); // prevent unwanted output
	require "./_include/fun_down.php";
	ob_end_clean(); // get rid of cached unwanted output
	download_item($current_dir, $GLOBALS["item"]);
	ob_start(false); // prevent unwanted output
	exit;
break;
case "download_selected":
	ob_start(); // prevent unwanted output
	require "./_include/fun_down.php";
	ob_end_clean(); // get rid of cached unwanted output
	download_selected($current_dir);
	ob_start(false); // prevent unwanted output
	exit;
break;

/**
  The file upload function.

  The user may choose between 3 uploader, the default (simple) one,
  uploadify (which is flashed based and not https capable) and ajaxupload.
  */
case "upload":
	$uploader = isset($GLOBALS["uploader"]) ? $GLOBALS["uploader"] : "default";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,7 +73,11 @@
 	ob_start(); // prevent unwanted output
 	require "./_include/fun_down.php";
 	ob_end_clean(); // get rid of cached unwanted output
-	download_item($current_dir, $GLOBALS["item"]);
+    global $item;
+    _debug("download item: $current_dir/$item");
+    if ($item == '' )
+        show_error($GLOBALS["error_msg"]["miscselitems"]);
+	download_item($current_dir, $item);
 	ob_start(false); // prevent unwanted output
 	exit;
 break;
```
