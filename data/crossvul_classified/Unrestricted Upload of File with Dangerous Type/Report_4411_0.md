# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 4411_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4411_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 1-32 of the vulnerable file.

<?php

namespace App\Controllers;

use Illuminate\Http\Request;
use App\Libs\Controller;
use Illuminate\Support\Facades\Storage;
use \Illuminate\Http\File;

class FileManagerController extends Controller{
 


    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index($slug){


        $mode = $this->request->get('mode');

        $current_dir = str_replace_first("storage/","",$this->request->get('path')==NULL? "" : ltrim($this->request->get('path'),"/"));

        $data = [
                'old_path' => ($current_dir==""? "":$current_dir."/"),
                'current_dir' => $current_dir,
                'dirs' => array_values(collect(\File::directories(storage_path($current_dir)))->map(function($dir){
                    return basename($dir);
                })->toArray()),
                'files' => array_values(collect(\File::files(storage_path($current_dir)))->map(function($file){
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,10 @@
 
 class FileManagerController extends Controller{
  
+
+    private function validationRegex(){
+        return '/^.*\.('.implode('|',["php","php5","php7"]).')$/i';
+    }
 
 
     /**
@@ -60,7 +64,10 @@
             if ($this->request->hasFile('up_file')){
 
                 foreach($this->request->up_file as $file){
-                   $images[] = $file->store(str_replace("storage/", "", $this->request->input('dir_path')));
+                    
+                    if(!preg_match($this->validationRegex(), strtolower($file))){
+                        $images[] = $file->store(str_replace("storage/", "", $this->request->input('dir_path')));
+                    }
                 }
 
                 if($this->request->ajax()){
@@ -223,7 +230,9 @@
 
         if($this->request->isMethod('POST')){
 
-            if(\Storage::move($this->request->input('old_file'), $this->request->input('new_file'))){
+            $new_file = $this->request->input('new_file');
+
+            if(!preg_match($this->validationRegex(), strtolower($new_file)) && \Storage::move($this->request->input('old_file'), $new_file)){
                 if($this->request->ajax()){
                     return response()->json(['success' => trans('File successfully renamed!')]);
                 }
```
