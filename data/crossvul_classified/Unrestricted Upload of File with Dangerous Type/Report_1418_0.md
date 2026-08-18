# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 1418_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1418_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 1-32 of the vulnerable file.

<?php
    if(isset($_FILES["fileUpload"]["name"])){
        $imageFile = ($_FILES["fileUpload"]["name"]);
        $imageType = ($_FILES["fileUpload"]["type"]);
        $validext = array("jpeg","jpg","png");
        $fileExt = pathinfo($imageFile, PATHINFO_EXTENSION);
        $ready = false;
        if((($imageType == "image/jpeg") || ($imageType == "image/jpg") || ($imageType == "image/png"))&&in_array($fileExt, $validext)){
            $ready = true;
        }else{
            echo "was not an image<br>";
        }

        if($_FILES["fileUpload"]["size"] < 1000000){
            $ready = true;
            echo "file size is ".$_FILES['fileUpload']["size"]."<br>";
        }else{
            echo "file was TOO BIG!";
        }

        if($_FILES["fileUpload"]["error"]){
            echo "looks like there was an error".$_FILES['fileUpload']["error"]."<br>";
            $ready = false;
        }

        $targetPath = "images/".$imageFile;
        $sourcePath = $_FILES["fileUpload"]["tmp_name"];
        if(file_exists("images/".$imageFile)){
            echo "File already there <br>";
            $ready = false;
        }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,7 @@
             $ready = true;
         }else{
             echo "was not an image<br>";
+            exit();
         }
 
         if($_FILES["fileUpload"]["size"] < 1000000){
@@ -16,11 +17,13 @@
             echo "file size is ".$_FILES['fileUpload']["size"]."<br>";
         }else{
             echo "file was TOO BIG!";
+            exit();
         }
 
         if($_FILES["fileUpload"]["error"]){
             echo "looks like there was an error".$_FILES['fileUpload']["error"]."<br>";
             $ready = false;
+            exit();
         }
 
         $targetPath = "images/".$imageFile;
@@ -28,6 +31,7 @@
         if(file_exists("images/".$imageFile)){
             echo "File already there <br>";
             $ready = false;
+            exit();
         }
 
         if($ready == true){
```
