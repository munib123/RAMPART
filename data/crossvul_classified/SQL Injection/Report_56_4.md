# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 56_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `56_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 1-37 of the vulnerable file.

<?php
/***************************************************************************
 *   copyright              : (C) 2008 - 2017 WeBid
 *   site                   : http://www.webidsupport.com/
 ***************************************************************************/

/***************************************************************************
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version. Although none of the code may be
 *   sold. If you have been sold this script, get a refund.
 ***************************************************************************/

include 'common.php';

$w = (isset($_GET['w'])) ? intval($_GET['w']) : '';
$_w = $w;
$fromfile = (isset($_GET['fromfile'])) ? $_GET['fromfile'] : '';
$nomanage = false;
$accepted_widths = array(
    $system->SETTINGS['thumb_show'],
    $system->SETTINGS['thumb_list'],
    430,
    '' // load default image
);
$w = (in_array($w, $accepted_widths)) ? $w : '';

function ErrorPNG($err)
{
    header('Content-type: image/png');
    $im = imagecreate(100, 30);
    $bgc = imagecolorallocate($im, 255, 255, 255);
    $tc = imagecolorallocate($im, 0, 0, 0);
    imagefilledrectangle($im, 0, 0, 100, 30, $bgc);
    imagestring($im, 1, 5, 5, $err, $tc);
    imagepng($im);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,9 +14,31 @@
 
 include 'common.php';
 
+// get passed values
 $w = (isset($_GET['w'])) ? intval($_GET['w']) : '';
-$_w = $w;
-$fromfile = (isset($_GET['fromfile'])) ? $_GET['fromfile'] : '';
+$fromfile = $_GET['fromfile'];
+$auction_id = $_GET['auction_id'];
+
+// check passed values
+if (!isset($_GET['fromfile']) ||
+	!isset($_GET['auction_id']) || !is_numeric($auction_id)) {
+    ErrorPNG($ERR_716);
+    exit;
+} elseif (!file_exists($_GET['fromfile']) && !fopen($_GET['fromfile'], 'r')) {
+    ErrorPNG($ERR_716);
+    exit;
+}
+
+if ($fromfile != '') {
+	// clean fromfile
+	$fromfile = basename($fromfile);
+	// build file path
+	$file_path = UPLOAD_FOLDER . $auction_id . '/' . $fromfile;
+} else {
+	// if empty filename just show default image
+	$file_path = MAIN_PATH . 'images/email_alerts/default_item_img.jpg';
+}
+
 $nomanage = false;
 $accepted_widths = array(
     $system->SETTINGS['thumb_show'],
@@ -47,17 +69,8 @@
     exit;
 }
 
-// control parameters and file existence
-if (!isset($_GET['fromfile']) || $fromfile == '') {
-    ErrorPNG($ERR_716);
-    exit;
-} elseif (!file_exists($_GET['fromfile']) && !fopen($_GET['fromfile'], 'r')) {
-    ErrorPNG($ERR_716);
-    exit;
-}
-
 if (file_exists(UPLOAD_PATH . 'cache/' . $w . '-' . md5($fromfile))) {
-    $img = getimagesize($fromfile);
+    $img = getimagesize($file_path);
     switch ($img[2]) {
         case IMAGETYPE_GIF:
             if (!(imagetypes() &IMG_GIF)) {
@@ -98,7 +111,7 @@
             mkdir(UPLOAD_PATH . 'cache', 0777);
         }
 
-        $img = @getimagesize($fromfile);
+        $img = @getimagesize($file_path);
         if (is_array($img)) {
             switch ($img[2]) {
                 case IMAGETYPE_GIF:
@@ -141,7 +154,7 @@
         }
         if ($w == '') {
             // just load the image
-            load_image($fromfile, $img['mime'], $image_type, $output_type);
+            load_image($file_path, $img['mime'], $image_type, $output_type);
         } else {
             // check image orientation
             if ($img[0] < $img[1]) {
@@ -156,9 +169,9 @@
             $ou = imagecreatetruecolor($w, $h);
             imagealphablending($ou, false);
             $funcall = "imagecreatefrom$image_type";
-            imagecopyresampled($ou, $funcall($fromfile), 0, 0, 0, 0, $w, $h, $img[0], $img[1]);
+            imagecopyresampled($ou, $funcall($file_path), 0, 0, 0, 0, $w, $h, $img[0], $img[1]);
             $funcall = "image$output_type";
-            $funcall($ou, UPLOAD_PATH . 'cache/' . $_w . '-' . md5($fromfile));
+            $funcall($ou, UPLOAD_PATH . 'cache/' . $w . '-' . md5($fromfile));
             header('Content-type: ' . $img['mime']);
             $funcall($ou);
             exit;
```
