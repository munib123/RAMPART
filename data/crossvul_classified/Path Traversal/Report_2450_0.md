# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 2450_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2450_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 363-407 of the vulnerable file.

                'debug' => $debug,
            ]
        );

    }

    public function downloadFiles() {
        App()->loadLibrary('admin.pclzip');
        
        $folder = basename(Yii::app()->request->getPost('folder', 'global'));
        $files = Yii::app()->request->getPost('files');

        $tempdir = Yii::app()->getConfig('tempdir');
        $randomizedFileName = $folder.'_'.substr(md5(time()),3,13).'.zip';
        $zipfile = $tempdir.DIRECTORY_SEPARATOR.$randomizedFileName;
        $arrayOfFiles = array_map( function($file){ return $file['path']; }, $files);
        $archive = new PclZip($zipfile);
        $checkFileCreate = $archive->create($arrayOfFiles, PCLZIP_OPT_REMOVE_ALL_PATH);
        $urlFormat = Yii::app()->getUrlManager()->getUrlFormat();
        $getFileLink = Yii::app()->createUrl('admin/filemanager/sa/getZipFile');
        if($urlFormat == 'path') {
            $getFileLink .= '?path='.$zipfile;
        } else {
            $getFileLink .= '&path='.$zipfile;
        }

        $this->_printJsonResponse(
            [
                'success' => true,
                'message' => sprintf(gT("Files are ready for download in archive %s."), $randomizedFileName),
                'downloadLink' => $getFileLink ,
            ]
        );
    }

    public function getZipFile($path) {
        $filename = basename($path);

        // echo "<pre>";
        // echo $path."\n";
        // echo $filename."\n";
        // echo "isFile => ".is_file($path) ? 'isFile' : 'isNoFile'."\n";
        // echo "</pre>";
        if (is_file($path) || true) {
            // Send the file for download!
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -380,11 +380,7 @@
         $checkFileCreate = $archive->create($arrayOfFiles, PCLZIP_OPT_REMOVE_ALL_PATH);
         $urlFormat = Yii::app()->getUrlManager()->getUrlFormat();
         $getFileLink = Yii::app()->createUrl('admin/filemanager/sa/getZipFile');
-        if($urlFormat == 'path') {
-            $getFileLink .= '?path='.$zipfile;
-        } else {
-            $getFileLink .= '&path='.$zipfile;
-        }
+        $_SESSION['__path'] = $zipfile;
 
         $this->_printJsonResponse(
             [
@@ -395,15 +391,16 @@
         );
     }
 
-    public function getZipFile($path) {
+    /**
+     * @return void
+     */
+    public function getZipFile()
+    {
+        $path = $_SESSION['__path'];
+        unset($_SESSION['__path']);
         $filename = basename($path);
 
-        // echo "<pre>";
-        // echo $path."\n";
-        // echo $filename."\n";
-        // echo "isFile => ".is_file($path) ? 'isFile' : 'isNoFile'."\n";
-        // echo "</pre>";
-        if (is_file($path) || true) {
+        if (is_file($path)) {
             // Send the file for download!
             header("Expires: 0");
             header("Cache-Control: must-revalidate");
```
