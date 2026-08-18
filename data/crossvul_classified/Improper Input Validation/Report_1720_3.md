# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 1720_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1720_3`)

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
  $paths = explode('/', $filename); 
  $nb_path = count($paths);
  foreach ($paths as $i => $path) {
    if ($i+1 == $nb_path) {
      $out .= $path;
    } else {
      $progres_path .= $path.'/';
      $out .= '<a href="'.get_url('plugin/file_manager/browse/'.rtrim($progres_path, '/')).'">'.$path.'</a>/';
    }
  }
?>
<h1><a href="<?php echo get_url('plugin/file_manager'); ?>">public</a>/<?php echo $out; ?></h1>
<?php if ($is_image) { ?>
  <img src="<?php echo BASE_FILES_DIR.'/'.$filename; ?>" />
<?php } else { ?>
<form method="post" action="<?php echo get_url('plugin/file_manager/save'); ?>">
    <div class="form-area">
        <p class="content">
            <label for="file_filter_id"><?php echo __('Filter'); ?></label>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,16 +23,26 @@
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
+
   $out = '';
   $progres_path = '';
-  $paths = explode('/', $filename); 
+  $paths = explode('/', $filename);
   $nb_path = count($paths);
   foreach ($paths as $i => $path) {
     if ($i+1 == $nb_path) {
       $out .= $path;
     } else {
+      $path = preg_replace('/.*:\/\/[^\/]+\//', '/', $path);
       $progres_path .= $path.'/';
-      $out .= '<a href="'.get_url('plugin/file_manager/browse/'.rtrim($progres_path, '/')).'">'.$path.'</a>/';
+      $out .= '<a href="'.get_url('plugin/file_manager/browse/'.rtrim($progres_path, '/')).'">'.htmlContextCleaner($path).'</a>/';
     }
   }
 ?>
```
