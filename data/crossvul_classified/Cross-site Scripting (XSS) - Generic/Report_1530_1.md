# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1530_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1530_1`)

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

        <h1><i class="fa fa-sitemap"></i> Menus
            <div class="pull-right">
                <button class="btn btn-success pull-right" data-toggle="modal" data-target="#myModal">
                    <span class="glyphicon glyphicon-plus"></span> Add Menu
                </button>
            </div>
        </h1>
        <hr />
    </div>
    <div class="col-sm-12">
        <div class="row">
            <div class="col-sm-12">
            <?php
                if (isset($data['menus']) && $data['menus'] != '') {
                    # code...
                     foreach (json_decode($data['menus']) as $k => $m) {
                        # code...
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,7 +12,37 @@
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
+    </button>
+    <ul>";
+    foreach ($data['alertgreen'] as $alert) {
+        # code...
+        echo "<li>$alert</li>\n";
+    }
+    echo "</ul></div>";
+}elseif (isset($data['alertred'])) {
+    # code...
+    //print_r($data['alertred']);
+    echo "<div class=\"alert alert-danger\" >
+    <button type=\"button\" class=\"close\" data-dismiss=\"alert\">
+        <span aria-hidden=\"true\">&times;</span>
+        <span class=\"sr-only\">Close</span>
+    </button>
+    <ul>";
+    foreach ($data['alertred'] as $alert) {
+        # code...
+        echo "<li>$alert</li>\n";
+    }
+    echo "</ul></div>";
+}
+?>
 <div class="row">
     <div class="col-md-12">
 
@@ -84,7 +114,7 @@
                                           </div>
                                           <div class=\"tab-pane\" id=\"{$k}additem\">
                                           ";
-                                              $data['parent'] = Menus::getParent('', $k);
+                                              $data['parent'] = Menus::isHadParent('', $k);
                                               //print_r($data['parent']);
                                               $data['menuid'] = $k;
                                               System::inc('menus_form', $data);
@@ -146,6 +176,7 @@
 
           </div>
           <div class="modal-footer">
+            <input type="hidden" name="token" value="<?=TOKEN;?>">
             <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
             <button type="submit" class="btn btn-success" name="submit">Save changes</button>
           </div>
```
