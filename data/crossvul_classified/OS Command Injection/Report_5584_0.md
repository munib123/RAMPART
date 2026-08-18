# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 5584_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5584_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 1-22 of the vulnerable file.

<?php

if (!session::checkAccessControl('gallery_allow_edit')){
    return;
}

include_once "coslib/upload.php";
moduleloader::includeModule ('gallery/admin');

class galleryUpload {
    
    public $errors = array ();
    public function form () {
        $values = html::specialEncode($values);

        html::formStart('gallery_upload');
        html::init($values, 'submit');
        $legend = lang::translate('gallery_upload_zip_legend');
        html::legend($legend);
        html::label('title', lang::system('system_form_label_title'));
        html::text('title');
        html::label('image_add', lang::translate('gallery_label_zip_add_chars'));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,5 @@
 <?php
+
 
 if (!session::checkAccessControl('gallery_allow_edit')){
     return;
@@ -71,8 +72,9 @@
                 return false;
             }
             
-            $zip = "/tmp/" . $_FILES['file']['name'];
-            $command = "mv " . $_FILES['file']['tmp_name'] . " $zip";
+            $zip = "/tmp/" . escapeshellcmd($_FILES['file']['name']);
+            //$zip = "/tmp/" . escapeshellcmd($_FILES['file']['name']);
+            $command = "mv " . escapeshellcmd($_FILES['file']['tmp_name']) . " $zip";
             //die;
             exec ($command, $output = array (), $res);
             if ($res) {
```
