# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1530_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1530_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-35 of the vulnerable file.

<?php
/**
* GeniXCMS - Content Management System
* 
* PHP Based Content Management System and Framework
*
* @package GeniXCMS
* @since 0.0.1 build date 20150202
* @version 0.0.1
* @link https://github.com/semplon/GeniXCMS
* @author Puguh Wijayanto (www.metalgenix.com)
* @copyright 2014-2015 Puguh Wijayanto
* @license http://www.opensource.org/licenses/mit-license.php MIT
*
*/?>
<div class="row">
    <div class="col-md-12">
        <h1><i class="fa fa-cubes"></i>  Categories 
            <button class="btn btn-success pull-right" data-toggle="modal" data-target="#myModal">
                <span class="glyphicon glyphicon-plus"></span> Add Category
            </button>
        </h1>
        <hr />
    </div>

    <div class="col-sm-12">
        <div class="row">
            <?php
                if($data['num'] > 0) {
                    foreach ($data['cat'] as $c) {
                        # code...
                        // echo "<td>".$c->id."</td>";
                        // echo "<td>".$c->name."</td>";
                        // echo "<td>".$c->parent."</td>";
                        // echo "<td></td>";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,7 +12,35 @@
 * @copyright 2014-2015 Puguh Wijayanto
 * @license http://www.opensource.org/licenses/mit-license.php MIT
 *
-*/?>
+*/
+
+if (isset($data['alertgreen'])) {
+    # code...
+    echo "<div class=\"alert alert-success\" >
+    <button type=\"button\" class=\"close\" data-dismiss=\"alert\">
+        <span aria-hidden=\"true\">&times;</span>
+        <span class=\"sr-only\">Close</span>
+    </button>";
+    foreach ($data['alertgreen'] as $alert) {
+        # code...
+        echo "$alert\n";
+    }
+    echo "</div>";
+}
+if (isset($data['alertred'])) {
+    # code...
+    echo "<div class=\"alert alert-danger\" >
+    <button type=\"button\" class=\"close\" data-dismiss=\"alert\">
+        <span aria-hidden=\"true\">&times;</span>
+        <span class=\"sr-only\">Close</span>
+    </button>";
+    foreach ($data['alertred'] as $alert) {
+        # code...
+        echo "$alert\n";
+    }
+    echo "</div>";
+}
+?>
 <div class="row">
     <div class="col-md-12">
         <h1><i class="fa fa-cubes"></i>  Categories 
@@ -34,12 +62,12 @@
                         // echo "<td>".$c->parent."</td>";
                         // echo "<td></td>";
 
-                        if($c->parent == ""){
+                        if($c->parent == "" || $c->parent == 0){
                             echo "<div class=\"col-md-4 item\" >
                             <div class=\"panel panel-default\">
                                 <div class=\"panel-heading\">
                                   <h3 class=\"panel-title\">{$c->name} 
-                                  <a href=\"?page=categories&act=del&id={$c->id}\" class=\"pull-right\"
+                                  <a href=\"?page=categories&act=del&id={$c->id}&token=".TOKEN."\" class=\"pull-right\"
                                   onclick=\"return confirm('Are you sure you want to delete this item?');\">
                                   <span class=\"glyphicon glyphicon-remove\"></span></a></h3>
                                 </div>
@@ -48,13 +76,14 @@
                                 foreach ($data['cat'] as $c2) {
                                     if($c2->parent == $c->id){
                                         echo "<li class=\"list-group-item\">
-                                        <form action=\"\" method=\"POST\" name=\"updatecat\">
+                                        <form action=\"index.php?page=categories\" method=\"POST\" name=\"updatecat\">
                                         <div class=\"input-group\">
-                                            <a href=\"?page=categories&act=del&id={$c2->id}\" class=\"input-group-addon\"
+                                            <a href=\"?page=categories&act=del&id={$c2->id}&token=".TOKEN."\" class=\"input-group-addon\"
                                             onclick=\"return confirm('Are you sure you want to delete this item?');\"
                                             ><span class=\"glyphicon glyphicon-remove\"></span></a>
                                             <input type=\"text\" name=\"cat\" class=\"form-control\" value=\"{$c2->name}\">
                                             <input type=\"hidden\" name=\"id\" value=\"{$c2->id}\">
+                                            <input type=\"hidden\" name=\"token\" value=\"".TOKEN."\">
                                             <span class=\"input-group-btn\">
                                                 <button class=\"btn btn-default\" type=\"submit\" name=\"updatecat\">Go!</button>
                                             </span>
@@ -92,7 +121,7 @@
                     <label>Parent</label>
                     <?php
                         $vars = array(
-                                    'parent' => '',
+                                    'parent' => '0',
                                     'name' => 'parent',
                                     'sort' => 'ASC',
                                     'order_by' => 'name'
@@ -107,6 +136,7 @@
             
           </div>
           <div class="modal-footer">
+            <input type="hidden" name="token" value="<?=TOKEN;?>">
             <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
             <button type="submit" class="btn btn-success" name="addcat">Save changes</button>
           </div>
```
