# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 1720_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1720_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 6-46 of the vulnerable file.

 *
 * This file is part of Wolf CMS. Wolf CMS is licensed under the GNU GPLv3 license.
 * Please see license.txt for the full license text.
 */

/**
 * The FileManager allows users to upload and manipulate files.
 *
 * @package Plugins
 * @subpackage file-manager
 *
 * @author Philippe Archambault <philippe.archambault@gmail.com>
 * @author Martijn van der Kleijn <martijn.niji@gmail.com>
 * @copyright Philippe Archambault & Martijn van der Kleijn, 2008
 * @license http://www.gnu.org/licenses/gpl.html GPLv3 license
 */

/* Security measure */
if (!defined('IN_CMS')) { exit(); }

  $out = '';
  $progres_path = '';
  $paths = explode('/', $dir); 
  $nb_path = count($paths)-1; // -1 to didn't display current dir as a link
  foreach ($paths as $i => $path) {
    if ($i+1 == $nb_path) {
      $out .= $path;
    } else if ($path != '') {
      $progres_path .= $path.'/';
      $out .= '<a href="'.get_url('plugin/file_manager/browse/'.rtrim($progres_path, '/')).'">'.$path.'</a>/';
    }
  }
?>
<h1><a href="<?php echo get_url('plugin/file_manager'); ?>">public</a>/<?php echo $out; ?></h1>
<table id="files-list" class="index" cellpadding="0" cellspacing="0" border="0">
  <thead>
    <tr>
      <th class="files"><?php echo __('File'); ?></th>
      <th class="size"><?php echo __('Size'); ?></th>
      <th class="permissions"><?php echo __('Permissions'); ?></th>
      <th class="mtime"><?php echo __('Modified'); ?></th>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,16 +23,25 @@
 /* Security measure */
 if (!defined('IN_CMS')) { exit(); }
 
+function htmlContextCleaner($input) {
+    $bad_chars = array("<", ">");
+    $safe_chars = array("&lt;", "&gt;");
+    $output = str_replace($bad_chars, $safe_chars, $input);
+
+    return stripslashes($output);
+}
+
   $out = '';
   $progres_path = '';
-  $paths = explode('/', $dir); 
+  $paths = explode('/', $dir);
   $nb_path = count($paths)-1; // -1 to didn't display current dir as a link
   foreach ($paths as $i => $path) {
     if ($i+1 == $nb_path) {
       $out .= $path;
     } else if ($path != '') {
+      $path = preg_replace('/.*:\/\/[^\/]+\//', '/', $path);
       $progres_path .= $path.'/';
-      $out .= '<a href="'.get_url('plugin/file_manager/browse/'.rtrim($progres_path, '/')).'">'.$path.'</a>/';
+      $out .= '<a href="'.get_url('plugin/file_manager/browse/'.rtrim($progres_path, '/')).'">'.htmlContextCleaner($path).'</a>/';
     }
   }
 ?>
@@ -74,11 +83,11 @@
 
   <div class="popup" id="chmod-popup" style="display:none;">
     <h3><?php echo __('Change mode'); ?></h3>
-    <form action="<?php echo get_url('plugin/file_manager/chmod'); ?>" method="post"> 
+    <form action="<?php echo get_url('plugin/file_manager/chmod'); ?>" method="post">
       <div>
         <input id="csrf_token" name="csrf_token" type="hidden" value="<?php echo SecureToken::generateToken(BASE_URL.'plugin/file_manager/chmod'); ?>" />
         <input id="chmod_file_name" name="file[name]" type="hidden" value="" />
-        <input id="chmod_file_mode" maxlength="4" name="file[mode]" type="text" value="" /> 
+        <input id="chmod_file_mode" maxlength="4" name="file[mode]" type="text" value="" />
         <input id="chmod_file_button" name="commit" type="submit" value="<?php echo __('Change mode'); ?>" />
       </div>
       <p><a class="close-link" href="#" onclick="toggle_chmod_popup(); return false;"><?php echo __('Close'); ?></a></p>
@@ -86,11 +95,11 @@
   </div>
   <div class="popup" id="rename-popup" style="display:none;">
       <h3><?php echo __('Rename'); ?></h3>
-      <form action="<?php echo get_url('plugin/file_manager/rename'); ?>" method="post"> 
+      <form action="<?php echo get_url('plugin/file_manager/rename'); ?>" method="post">
         <div>
           <input id="csrf_token" name="csrf_token" type="hidden" value="<?php echo SecureToken::generateToken(BASE_URL.'plugin/file_manager/rename'); ?>" />
           <input id="rename_file_current_name" name="file[current_name]" type="hidden" value="" />
-          <input id="rename_file_new_name" maxlength="50" name="file[new_name]" type="text" value="" /> 
+          <input id="rename_file_new_name" maxlength="50" name="file[new_name]" type="text" value="" />
           <input id="rename_file_button" name="commit" type="submit" value="<?php echo __('Rename'); ?>" />
         </div>
         <p><a class="close-link" href="#" onclick="toggle_rename_popup(); return false;"><?php echo __('Close'); ?></a></p>
```
