# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 4371_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4371_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 1-21 of the vulnerable file.

<?php 

namespace Kirby\Panel\Models\Page;

use Error;
use Exception;
use F;
use Str;
use Kirby\Panel\Event;
use Kirby\Panel\Upload;

class Uploader {

  public $kirby;
  public $page;
  public $file;
  public $blueprint;
  public $filename;

  public function __construct($page, $file = null) {

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-<?php 
+<?php
 
 namespace Kirby\Panel\Models\Page;
 
@@ -27,7 +27,7 @@
     if($this->file) {
       $this->replace();
     } else {
-      $this->upload();      
+      $this->upload();
     }
 
   }
@@ -55,7 +55,7 @@
     // create the initial meta file
     // without triggering the update hook
     try {
-      $file->createMeta(false);      
+      $file->createMeta(false);
     } catch(Exception $e) {
       // don't react on meta errors
       // the meta file can still be generated later
@@ -64,13 +64,13 @@
     // make sure that the file is being marked as updated
     touch($file->root());
 
-    kirby()->trigger($event, $file);          
+    kirby()->trigger($event, $file);
 
   }
 
   public function replace() {
 
-    $file   = $this->file;    
+    $file   = $this->file;
     $upload = new Upload($file->root(), array(
       'overwrite' => true,
       'accept' => function($upload) use($file) {
@@ -135,7 +135,7 @@
   public function checkUpload($file) {
 
     $filesettings        = $this->blueprint->files();
-    $forbiddenExtensions = array('php', 'html', 'htm', 'exe', kirby()->option('content.file.extension', 'txt'));
+    $forbiddenExtensions = array('php', 'phar', 'html', 'htm', 'exe', kirby()->option('content.file.extension', 'txt'));
     $forbiddenMimes      = array_merge(f::$mimes['php'], array('text/html', 'application/x-msdownload'));
     $extension           = strtolower($file->extension());
 
@@ -150,7 +150,7 @@
     }
 
     // especially block any connection that contains php
-    if(str::contains($extension, 'php')) {
+    if(str::contains($extension, 'php') || str::contains($extension, 'phar')) {
       throw new Exception(l('files.add.error.extension.forbidden'));
     }
 
@@ -187,7 +187,7 @@
     // Files blueprint option 'height'
     if($file->type() == 'image' and $filesettings->height() and $file->height() > $filesettings->height()) {
       throw new Exception('Page only allows image height of ' . $filesettings->height().'px');
-    } 
+    }
 
   }
 
```
