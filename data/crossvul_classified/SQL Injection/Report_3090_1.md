# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3090_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3090_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 1-60 of the vulnerable file.

<?php
/**
 * GeniXCMS - Content Management System.
 *
 * PHP Based Content Management System and Framework
 *
 * @since 0.0.1 build date 20150202
 *
 * @version 1.0.0
 *
 * @link https://github.com/semplon/GeniXCMS
 * @link http://genixcms.org
 *
 * @author Puguh Wijayanto <psw@metalgenix.com>
 * @copyright 2014-2016 Puguh Wijayanto
 * @license http://www.opensource.org/licenses/mit-license.php MIT
 */
if (isset($data['alertSuccess'])) {
    
    echo '<div class="alert alert-success" >
    <button type="button" class="close" data-dismiss="alert">
        <span aria-hidden="true">&times;</span>
        <span class="sr-only">'.CLOSE.'</span>
    </button>';
    foreach ($data['alertSuccess'] as $alert) {
        
        echo "$alert\n";
    }
    echo '</div>';
}
if (isset($data['alertDanger'])) {
    
    echo '<div class="alert alert-danger" >
    <button type="button" class="close" data-dismiss="alert">
        <span aria-hidden="true">&times;</span>
        <span class="sr-only">'.CLOSE.'</span>
    </button>';
    foreach ($data['alertDanger'] as $alert) {
        
        echo "$alert\n";
    }
    echo '</div>';
}
?>
<div class="row">
    <div class="col-md-12">
        <?=Hooks::run('admin_page_notif_action', $data);?>
    </div>
    <div class="col-md-12">
        <h1><i class="fa fa-photo"></i>  Media

        </h1>
        <hr />
    </div>

    <div class="col-sm-12">
        <div class="row">
            <div id="elfinder"></div>
        </div>

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,32 +15,7 @@
  * @copyright 2014-2016 Puguh Wijayanto
  * @license http://www.opensource.org/licenses/mit-license.php MIT
  */
-if (isset($data['alertSuccess'])) {
-    
-    echo '<div class="alert alert-success" >
-    <button type="button" class="close" data-dismiss="alert">
-        <span aria-hidden="true">&times;</span>
-        <span class="sr-only">'.CLOSE.'</span>
-    </button>';
-    foreach ($data['alertSuccess'] as $alert) {
-        
-        echo "$alert\n";
-    }
-    echo '</div>';
-}
-if (isset($data['alertDanger'])) {
-    
-    echo '<div class="alert alert-danger" >
-    <button type="button" class="close" data-dismiss="alert">
-        <span aria-hidden="true">&times;</span>
-        <span class="sr-only">'.CLOSE.'</span>
-    </button>';
-    foreach ($data['alertDanger'] as $alert) {
-        
-        echo "$alert\n";
-    }
-    echo '</div>';
-}
+
 ?>
 <div class="row">
     <div class="col-md-12">
@@ -54,11 +29,6 @@
     </div>
 
     <div class="col-sm-12">
-        <div class="row">
-            <div id="elfinder"></div>
-        </div>
-
-
-
+        <div id="elfinder"></div>
     </div>
 </div>
```
