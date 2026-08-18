# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5588_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5588_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-28 of the vulnerable file.

<?php
include_once("./eval_conf.php");
include_once("./functions.php");
include_once("./global.php");

if (! checkAccess(GangliaAcl::ALL_VIEWS, GangliaAcl::VIEW, $conf))
  die("You do not have access to view views.");

///////////////////////////////////////////////////////////////////////////////
// Create new view
///////////////////////////////////////////////////////////////////////////////
if (isset($_GET['create_view'])) {
  if(! checkAccess(GangliaAcl::ALL_VIEWS, GangliaAcl::EDIT, $conf)) {
    $output = "You do not have access to edit views.";
  } else {
    // Check whether the view name already exists
    $view_exists = 0;

    $available_views = get_available_views();

    foreach ($available_views as $view_id => $view) {
      if ($view['view_name'] == $_GET['view_name']) {
        $view_exists = 1;
      }
    }

    if ($view_exists == 1) {
      $output = "<strong>Alert:</strong> View with the name " .
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,20 @@
 
 if (! checkAccess(GangliaAcl::ALL_VIEWS, GangliaAcl::VIEW, $conf))
   die("You do not have access to view views.");
+
+$user['view_name'] = $_REQUEST['view_name'];
+
+if( !is_proper_view_name ( $user['view_name'])){
+?>
+<div class="ui-widget">
+  <div class="ui-state-default ui-corner-all" styledefault="padding: 0 .7em;"> 
+    <p><span class="ui-icon ui-icon-alert" style="float: left; margin-right: .3em;"></span> 
+    View names valid characters are 0-9, a-z, A-Z, -, _ and space. View has not been created.</p>
+  </div>
+</div>
+<?php
+  exit(0);
+}
 
 ///////////////////////////////////////////////////////////////////////////////
 // Create new view
@@ -19,19 +33,20 @@
     $available_views = get_available_views();
 
     foreach ($available_views as $view_id => $view) {
-      if ($view['view_name'] == $_GET['view_name']) {
+      if ($view['view_name'] == $user['view_name']) {
         $view_exists = 1;
+        break;
       }
     }
 
     if ($view_exists == 1) {
       $output = "<strong>Alert:</strong> View with the name " .
-                $_GET['view_name'] . 
+                $user['view_name'] . 
                 " already exists.";
     } else {
-      $empty_view = array ("view_name" => $_GET['view_name'],
+      $empty_view = array ("view_name" => $user['view_name'],
                            "items" => array());
-      $view_suffix = str_replace(" ", "_", $_GET['view_name']);
+      $view_suffix = str_replace(" ", "_", $user['view_name']);
       $view_filename = $conf['views_dir'] . "/view_" . preg_replace('/[^a-zA-Z0-9_-]/', '', $view_suffix) . ".json";
       if ( pathinfo( $view_filename, PATHINFO_DIRNAME ) != $conf['views_dir'] ) {
         die('Invalid path detected');
@@ -71,17 +86,18 @@
     $available_views = get_available_views();
 
     foreach ($available_views as $view_id => $view) {
-      if ($view['view_name'] == $_GET['view_name']) {
+      if ($view['view_name'] == $user['view_name']) {
         $view_exists = 1;
+        break;
       }
     }
 
     if ($view_exists != 1) {
       $output = "<strong>Alert:</strong> View with the name " .
-      $_GET['view_name'] . 
+      $user['view_name'] . 
       " does not exist.";
     } else {
-      $view_suffix = str_replace(" ", "_", $_GET['view_name']);
+      $view_suffix = str_replace(" ", "_", $user['view_name']);
       $view_filename = $conf['views_dir'] . "/view_" . preg_replace('/[^a-zA-Z0-9_-]/', '', $view_suffix) . ".json";
       if ( pathinfo( $view_filename, PATHINFO_DIRNAME ) != $conf['views_dir'] ) {
         die('Invalid path detected');
@@ -109,7 +125,7 @@
     $available_views = get_available_views();
 
     foreach ($available_views as $view_id => $view) {
-      if ($view['view_name'] == $_GET['view_name']) {
+      if ($view['view_name'] == $user['view_name']) {
         $view_exists = 1;
         break;
       }
@@ -117,7 +133,7 @@
 
     if ($view_exists == 0) {
       $output = "<strong>Alert:</strong> View " .
-      $_GET['view_name'] . 
+      $user['view_name'] . 
       " does not exist. This should not happen.";
     } else {
       // Read in contents of an existing view
```
