# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 4959_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4959_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-41 of the vulnerable file.

<?php
/************************************************************************/
/* ATutor                                                               */
/************************************************************************/
/* Copyright (c) 2002-2010                                              */
/* Inclusive Design Institute                                           */
/* http://atutor.ca                                                     */
/*                                                                      */
/* This program is free software. You can redistribute it and/or        */
/* modify it under the terms of the GNU General Public License          */
/* as published by the Free Software Foundation.                        */
/************************************************************************/
// $Id: 

define('AT_INCLUDE_PATH', '../../../include/');
require (AT_INCLUDE_PATH.'vitals.inc.php');
admin_authenticate(AT_ADMIN_PRIV_MODULES);
require(AT_INCLUDE_PATH.'../mods/_core/modules/classes/ModuleListParser.class.php');
require_once(AT_INCLUDE_PATH.'../mods/_core/file_manager/filemanager.inc.php');
// delete all folders and files in $dir
function clear_dir($dir)
{
	if ($dh = opendir($dir)) 
	{
		while (($file = readdir($dh)) !== false)
		{
			if (($file == '.') || ($file == '..'))
				continue;

			if (is_dir($dir.$file)) 
				clr_dir($dir.$file);
			else 
				unlink($dir.$file);
		}
		
		closedir($dh);
	}
}

set_time_limit(0);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,6 +18,8 @@
 require(AT_INCLUDE_PATH.'../mods/_core/modules/classes/ModuleListParser.class.php');
 require_once(AT_INCLUDE_PATH.'../mods/_core/file_manager/filemanager.inc.php');
 // delete all folders and files in $dir
+
+
 function clear_dir($dir)
 {
 	if ($dh = opendir($dir)) 
@@ -154,8 +156,15 @@
 
 			if (!$msg->containsErrors())
 			{
-				header('Location: module_install_step_1.php?mod='.urlencode($module_folder).SEP.'new=1');
-				exit;
+			        if($_POST['csrftoken'] != $_SESSION['token']){
+                        $msg->addError('ACCESS_DENIED');
+                    } else {
+                    
+                        header('Location: module_install_step_1.php?mod='.urlencode($module_folder).SEP.'new=1');                        
+                        exit;
+                    }
+				//header('Location: module_install_step_1.php?mod='.urlencode($module_folder).SEP.'new=1');
+				//exit;
 			}
 		}
 		
@@ -181,8 +190,13 @@
 	$dir_name = str_replace(array('.','..'), '', $_POST['mod']);
 
 	if (isset($_POST['install_manually'])) {
-		header('Location: '.AT_BASE_HREF.'mods/_core/modules/module_install_step_2.php?mod='.urlencode($dir_name).SEP.'new=1'.SEP.'mod_in=1');
-		exit;
+	// Check for potential  CSRF
+        if($_POST['csrftoken'] != $_SESSION['token']){
+                $msg->addError('ACCESS_DENIED');
+        } else {
+            header('Location: '.AT_BASE_HREF.'mods/_core/modules/module_install_step_2.php?mod='.urlencode($dir_name).SEP.'new=1'.SEP.'mod_in=1');
+            exit;
+        }
 	}
 
 } else if (isset($_POST['install_manually'])) {
@@ -255,16 +269,18 @@
 
     // Add $module_list_array as the last parameter, to sort by the common key
     // Sorts by original $module_list_array by reference, then returns true|false
-    $sort_by_version = array_multisort($version, SORT_DESC, $module_list_array);
+    //$sort_by_version = array_multisort($version, SORT_DESC, $module_list_array);
 
 // Create menu for filter ATutor versions
-function select_atversion(){ 
+function select_atversion($v=0){ 
     global $sort_versions;
     $menu = '<form action="'.$_SERVER['PHP_SELF'].'" method="post">'; 
     $menu.= '<select name="atversions">';
     $menu.= '<option value="0">'._AT("all").'</option>';
     foreach($sort_versions as $version){
-        if($version == VERSION){
+        if($version == $v){
+            $menu .= '<option value="'.$version.'" selected="selected">'.$version.'</option>';
+        }else if($version == VERSION){
             $menu .= '<option value="'.$version.'" selected="selected">'.$version.'</option>';
         }else{
             $menu .= '<option value="'.$version.'" >'.$version.'</option>';
```
