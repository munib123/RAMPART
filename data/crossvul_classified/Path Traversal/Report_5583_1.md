# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 5583_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5583_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 1-24 of the vulnerable file.

<?php

require_once "_include/session.php";

//------------------------------------------------------------------------------
// THESE ARE NUMEROUS HELPER FUNCTIONS FOR THE OTHER INCLUDE FILES
//------------------------------------------------------------------------------
function make_link($_action,$_dir,$_item=NULL,$_order=NULL,$_srt=NULL,$_lang=NULL) {
						// make link to next page
	if($_action=="" || $_action==NULL) $_action="list";
	if($_dir=="") $_dir=NULL;
	if($_item=="") $_item=NULL;
	if($_order==NULL) $_order=$GLOBALS["order"];
	if($_srt==NULL) $_srt=$GLOBALS["srt"];
	if($_lang==NULL) $_lang=(isset($GLOBALS["lang"])?$GLOBALS["lang"]:NULL);

	$link=$GLOBALS["script_name"]."?action=".$_action;
	if($_dir!=NULL) $link.="&dir=".urlencode($_dir);
	if($_item!=NULL) $link.="&item=".urlencode($_item);
	if($_order!=NULL) $link.="&order=".$_order;
	if($_srt!=NULL) $link.="&srt=".$_srt;
	if($_lang!=NULL) $link.="&lang=".$_lang;

	return $link;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,8 @@
 <?php
 
 require_once "_include/session.php";
+require_once "_include/qxpath.php";
+require_once "_include/str.php";
 
 //------------------------------------------------------------------------------
 // THESE ARE NUMEROUS HELPER FUNCTIONS FOR THE OTHER INCLUDE FILES
@@ -30,7 +32,7 @@
 }
 
 function get_abs_item($dir, $item) {		// get absolute file+path
-	return get_abs_dir($dir).DIRECTORY_SEPARATOR.$item;
+	return realpath(get_abs_dir($dir).DIRECTORY_SEPARATOR.$item);
 }
 /**
   get file relative from home
@@ -40,9 +42,15 @@
     return $dir == "" ? $item : "$dir/$item";
 }
 
-function get_is_file($dir, $item) {		// can this file be edited?
-	return @is_file(get_abs_item($dir,$item));
-}
+/**
+  can this file be edited?
+  */
+function get_is_file($dir, $item)
+{
+    $filename = get_abs_item($dir, $item);
+	return @is_file($filename);
+}
+
 //------------------------------------------------------------------------------
 function get_is_dir($dir, $item) {		// is this a directory?
 	return @is_dir(get_abs_item($dir,$item));
@@ -182,31 +190,45 @@
  */
 function get_show_item ($directory, $file)
 {
+    // no relative paths are allowed in directories
     if ( preg_match( "/\.\./", $directory ) )
         return false;
 
-    if ( isset($file) && preg_match( "/\.\./", $file ) )
-        return false;
-
-    // dont display own directory
-    if ( $file == "." )
-        return false;
-
-    if ( substr( $file, 0, 1) == "." && $GLOBALS["show_hidden"] == false )
-        return false;
+    if ( isset($file) )
+    {
+        // file name must not contain any path separators
+        if ( preg_match( "/[\/\\\\]/", $file ) )
+            return false;
+
+        // dont display own and parent directory
+        if ( $file == "." || $file == ".." )
+            return false;
+
+        // determine full path to the file
+        $full_path = get_abs_item( $directory, $file );
+        _debug("full_path: $full_path");
+        if ( ! str_startswith( $full_path, path_f() ) )
+            return false;
+    }
+
+    // check if user is allowed to acces shidden files
+    global $show_hidden;
+    if ( ! $show_hidden )
+    {
+        if ( $file[0] == '.' )
+            return false;
+
+        // no part of the path may be hidden
+        $directory_parts = explode( "/", $directory );
+        foreach ( $directory_parts as $directory_part )
+        {
+            if ( $directory_part[0] == '.' )
+                return false;
+        }
+    }
 
     if (matches_noaccess_pattern($file))
         return false;
-
-    if ( $GLOBALS["show_hidden"] == false )
-    {
-      $directory_parts = explode( "/", $directory );
-      foreach ($directory_parts as $directory_part )
-      {
-        if ( substr ( $directory_part, 0, 1) == "." )
-          return false;
-      }
-    }
 
     return true;
 }
```
