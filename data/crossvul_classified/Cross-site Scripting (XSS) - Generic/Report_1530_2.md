# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1530_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1530_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 2-42 of the vulnerable file.

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
*/

    if(isset($_GET['id'])){
        $menuid = $_GET['id'];
    }else{
        $menuid = $data['menuid'];
    }
?>
<form action="" method="POST">
<h1><i class="fa fa-sitemap"></i> Add Menu
<div class="pull-right">
<button type="submit" name="additem" class="btn btn-success">
    <span class="glyphicon glyphicon-ok"></span>
    Submit
</button>
<a href="index.php?page=menus" class="btn btn-danger">
    <span class="glyphicon glyphicon-remove"></span>
    Cancel
</a>
</div>
</h1>
<div class="col-sm-12">
    <div class="col-sm-4">
        <div class="form-group">
            <label>Parent Menu</label>
            <select class="form-control" name="parent">
                <option></option>
            <?php
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,35 @@
     }else{
         $menuid = $data['menuid'];
     }
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
+
 ?>
 <form action="" method="POST">
 <h1><i class="fa fa-sitemap"></i> Add Menu
@@ -142,4 +171,5 @@
         </div>
     </div>
 </div>
+<input type="hidden" name="token" value="<?=TOKEN;?>">
 </form>
```
