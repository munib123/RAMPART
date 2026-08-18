# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3982_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3982_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 1-26 of the vulnerable file.

<?php
//Default Configuration
$CONFIG = '{"lang":"en","error_reporting":false,"show_hidden":false,"hide_Cols":false,"calc_folder":false}';

/**
 * H3K | Tiny File Manager V2.4.1
 * CCP Programmers | ccpprogrammers@gmail.com
 * https://tinyfilemanager.github.io
 */

//TFM version
define('VERSION', '2.4.1');

//Application Title
define('APP_TITLE', 'Tiny File Manager');

// --- EDIT BELOW CONFIGURATION CAREFULLY ---


// Auth with login/password 
// set true/false to enable/disable it
// Is independent from IP white- and blacklisting
$use_auth = true;

// Login user name and password
// Users: array('Username' => 'Password', 'Username2' => 'Password2', ...)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,13 +3,13 @@
 $CONFIG = '{"lang":"en","error_reporting":false,"show_hidden":false,"hide_Cols":false,"calc_folder":false}';
 
 /**
- * H3K | Tiny File Manager V2.4.1
+ * H3K | Tiny File Manager V2.4.2
  * CCP Programmers | ccpprogrammers@gmail.com
  * https://tinyfilemanager.github.io
  */
 
 //TFM version
-define('VERSION', '2.4.1');
+define('VERSION', '2.4.2');
 
 //Application Title
 define('APP_TITLE', 'Tiny File Manager');
@@ -417,7 +417,7 @@
     //search : get list of files from the current folder
     if(isset($_POST['type']) && $_POST['type']=="search") {
         $dir = FM_ROOT_PATH;
-        $response = scan($_POST['path'], $_POST['content']);
+        $response = scan(fm_clean_path($_POST['path']), $_POST['content']);
         echo json_encode($response);
         exit();
     }
@@ -425,11 +425,16 @@
     // backup files
     if (isset($_POST['type']) && $_POST['type'] == "backup") {
         $file = $_POST['file'];
-        $path = $_POST['path'];
-        $date = date("dMy-His");
-        $newFile = $file . '-' . $date . '.bak';
-        copy($path . '/' . $file, $path . '/' . $newFile) or die("Unable to backup");
-        echo "Backup $newFile Created";
+        $dir = fm_clean_path($_POST['path']);
+        $path = FM_ROOT_PATH.'/'.$dir;
+        if($dir) {
+            $date = date("dMy-His");
+            $newFile = $file . '-' . $date . '.bak';
+            copy($path . '/' . $file, $path . '/' . $newFile) or die("Unable to backup");
+            echo "Backup $newFile Created";
+        } else {
+            echo "Error! Not allowed";
+        }
     }
 
     // Save Config
@@ -785,17 +790,7 @@
         $path .= '/' . FM_PATH;
     }
     if ($dl != '' && is_file($path . '/' . $dl)) {
-        header('Content-Description: File Transfer');
-        header('Content-Type: application/octet-stream');
-        header('Content-Disposition: attachment; filename="' . basename($path . '/' . $dl) . '"');
-        header('Content-Transfer-Encoding: binary');
-        header('Connection: Keep-Alive');
-        header('Expires: 0');
-        header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
-        header('Pragma: public');
-        header('Content-Length: ' . filesize($path . '/' . $dl));
-        ob_end_clean();
-        readfile($path . '/' . $dl);
+        fm_download_file($path . '/' . $dl, $dl, 1024);
         exit;
     } else {
         fm_set_msg('File not found', 'error');
@@ -816,6 +811,10 @@
     $errors = 0;
     $uploads = 0;
     $allowed = (FM_UPLOAD_EXTENSION) ? explode(',', FM_UPLOAD_EXTENSION) : false;
+    $response = array (
+        'status' => 'error',
+        'info'   => 'Oops! Try again'
+    );
 
     $filename = $f['file']['name'];
     $tmp_name = $f['file']['tmp_name'];
@@ -989,8 +988,17 @@
             $zipper = new FM_Zipper();
             $res = $zipper->unzip($zip_path, $path);
         } elseif ($ext == "tar") {
-            $gzipper = new PharData($zip_path);
-            $res = $gzipper->extractTo($path);
+            try {
+                $gzipper = new PharData($zip_path);
+                if (@$gzipper->extractTo($path,null, true)) {
+                    $res = true;
+                } else {
+                    $res = false;
+                }
+            } catch (Exception $e) {
+                //TODO:: need to handle the error
+                $res = true;
+            }
         }
 
         if ($res) {
@@ -1137,7 +1145,7 @@
                     <?php echo lng('DestinationFolder') ?>: <?php echo fm_enc(fm_convert_win(FM_ROOT_PATH . '/' . FM_PATH)) ?>
                 </p>
 
-                <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]) . '?p=' . fm_enc(FM_PATH) ?>" class="dropzone card-tabs-container" id="fileUploader" enctype="multipart/form-data">
+                <form action="<?php echo htmlspecialchars(FM_SELF_URL) . '?p=' . fm_enc(FM_PATH) ?>" class="dropzone card-tabs-container" id="fileUploader" enctype="multipart/form-data">
                     <input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
                     <input type="hidden" name="fullpath" id="fullpath" value="<?php echo fm_enc(FM_PATH) ?>">
                     <div class="fallback">
@@ -1707,7 +1715,7 @@
             </div>
             <div class="edit-file-actions col-xs-12 col-sm-7 col-lg-6 text-right pt-1">
                 <a title="Back" class="btn btn-sm btn-outline-primary" href="?p=<?php echo urlencode(trim(FM_PATH)) ?>&amp;view=<?php echo urlencode($file) ?>"><i class="fa fa-reply-all"></i> <?php echo lng('Back') ?></a>
-                <a title="Backup" class="btn btn-sm btn-outline-primary" href="javascript:backup('<?php echo urlencode($path) ?>','<?php echo urlencode($file) ?>')"><i class="fa fa-database"></i> <?php echo lng('BackUp') ?></a>
+                <a title="Backup" class="btn btn-sm btn-outline-primary" href="javascript:void(0);" onclick="backup('<?php echo urlencode(trim(FM_PATH)) ?>','<?php echo urlencode($file) ?>')"><i class="fa fa-database"></i> <?php echo lng('BackUp') ?></a>
                 <?php if ($is_text) { ?>
                     <?php if ($isNormalEditor) { ?>
                         <a title="Advanced" class="btn btn-sm btn-outline-primary" href="?p=<?php echo urlencode(trim(FM_PATH)) ?>&amp;edit=<?php echo urlencode($file) ?>&amp;env=ace"><i class="fa fa-pencil-square-o"></i> <?php echo lng('AdvancedEditor') ?></a>
@@ -2809,29 +2817,142 @@
     return array('doc', 'docx', 'xls', 'xlsx', 'pdf', 'ppt', 'pptx', 'ai', 'psd', 'dxf', 'xps', 'rar', 'odt', 'ods');
 }
 
+function fm_get_file_mimes($extension)
+{
+    $fileTypes['swf'] = 'application/x-shockwave-flash';
+    $fileTypes['pdf'] = 'application/pdf';
+    $fileTypes['exe'] = 'application/octet-stream';
+    $fileTypes['zip'] = 'application/zip';
+    $fileTypes['doc'] = 'application/msword';
+    $fileTypes['xls'] = 'application/vnd.ms-excel';
+    $fileTypes['ppt'] = 'application/vnd.ms-powerpoint';
+    $fileTypes['gif'] = 'image/gif';
+    $fileTypes['png'] = 'image/png';
+    $fileTypes['jpeg'] = 'image/jpg';
+    $fileTypes['jpg'] = 'image/jpg';
+    $fileTypes['rar'] = 'application/rar';
+
+    $fileTypes['ra'] = 'audio/x-pn-realaudio';
+    $fileTypes['ram'] = 'audio/x-pn-realaudio';
+    $fileTypes['ogg'] = 'audio/x-pn-realaudio';
+
+    $fileTypes['wav'] = 'video/x-msvideo';
+    $fileTypes['wmv'] = 'video/x-msvideo';
+    $fileTypes['avi'] = 'video/x-msvideo';
+    $fileTypes['asf'] = 'video/x-msvideo';
+    $fileTypes['divx'] = 'video/x-msvideo';
+
+    $fileTypes['mp3'] = 'audio/mpeg';
+    $fileTypes['mp4'] = 'audio/mpeg';
+    $fileTypes['mpeg'] = 'video/mpeg';
+    $fileTypes['mpg'] = 'video/mpeg';
+    $fileTypes['mpe'] = 'video/mpeg';
+    $fileTypes['mov'] = 'video/quicktime';
+    $fileTypes['swf'] = 'video/quicktime';
+    $fileTypes['3gp'] = 'video/quicktime';
+    $fileTypes['m4a'] = 'video/quicktime';
+    $fileTypes['aac'] = 'video/quicktime';
+    $fileTypes['m3u'] = 'video/quicktime';
+
+    $fileTypes['php'] = ['application/x-php'];
+    $fileTypes['html'] = ['text/html'];
+    $fileTypes['txt'] = ['text/plain'];
+    return $fileTypes[$extension];
+}
+
 /**
  * This function scans the files and folder recursively, and return matching files
  * @param string $dir
+ * @param string $filter
  * @return json
  */
  function scan($dir, $filter = '') {
     $path = FM_ROOT_PATH.'/'.$dir;
-    $ite = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path));
-    $rii = new RegexIterator($ite, "/(".$filter.")/i");
-
-    $files = array(); 
-    foreach ($rii as $file) {
-        if (!$file->isDir()) {
-            $fileName = $file->getFilename();
-            $location = str_replace(FM_ROOT_PATH, '', $file->getPath());
-            $files[] = array(
-                    "name" => $fileName,
-                    "type" => "file",
-                    "path" => $location,
-                );           
... (diff truncated)
```
