# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5560_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5560_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-38 of the vulnerable file.

<?php

include_once("./eval_conf.php");
include_once("./functions.php");

if ( isset($_GET['action']) && $_GET['action'] == "show_views" ) {
  //////////////////////////////////////////////////////////////////////////////////////////////////////
  // Show available views
  //////////////////////////////////////////////////////////////////////////////////////////////////////
  $available_views = get_available_views();
  ?>

  <table>
  <?php
  if ( isset($_GET['aggregate']) ) {
  ?>
     <tr><th>Host regular expression</th><td><?php print join (",", $_GET['hreg']); ?></td></tr>
     <tr><th>Metric regular expression</th><td><?php print join (",", $_GET['mreg']); ?></td></tr>
  <?php
    } else {
  ?>
     <tr><th>Hostname</th><td><?php print $_GET['host_name']; ?></td></tr>
     <tr><th>Metric/Report</th><td><?php print $_GET['metric_name']; ?></td></tr>
  <?php
  }
  ?>

  </table>
  <p>
  <form id="add_metric_to_view_form">
    Add graph to view: <br />
    <?php 
    // Get all the aggregate form variables and put them in the hidden fields
    if ( isset($_GET['aggregate']) ) {
	foreach ( $_GET as $key => $value ) {
	  if ( is_array($value) ) {
	    foreach ( $value as $index => $value2 ) {
	      print '<input type="hidden" name="' . $key .'[]" value="' . $value2 . '" />';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,13 +14,13 @@
   <?php
   if ( isset($_GET['aggregate']) ) {
   ?>
-     <tr><th>Host regular expression</th><td><?php print join (",", $_GET['hreg']); ?></td></tr>
-     <tr><th>Metric regular expression</th><td><?php print join (",", $_GET['mreg']); ?></td></tr>
+     <tr><th>Host regular expression</th><td><?php print htmlspecialchars( join (",", $_GET['hreg']) ); ?></td></tr>
+     <tr><th>Metric regular expression</th><td><?php print htmlspecialchars( join (",", $_GET['mreg']) ); ?></td></tr>
   <?php
     } else {
   ?>
-     <tr><th>Hostname</th><td><?php print $_GET['host_name']; ?></td></tr>
-     <tr><th>Metric/Report</th><td><?php print $_GET['metric_name']; ?></td></tr>
+     <tr><th>Hostname</th><td><?php print htmlspecialchars($_GET['host_name']); ?></td></tr>
+     <tr><th>Metric/Report</th><td><?php print htmlspecialchars($_GET['metric_name']); ?></td></tr>
   <?php
   }
   ?>
@@ -35,17 +35,17 @@
 	foreach ( $_GET as $key => $value ) {
 	  if ( is_array($value) ) {
 	    foreach ( $value as $index => $value2 ) {
-	      print '<input type="hidden" name="' . $key .'[]" value="' . $value2 . '" />';
+	      print '<input type="hidden" name="' . htmlspecialchars($key) .'[]" value="' . htmlspecialchars($value2) . '" />';
 	    }
 	  } else {
-	    print '<input type="hidden" name="' . $key .'" value="' . $value . '" />';
+	    print '<input type="hidden" name="' . htmlspecialchars($key) .'" value="' . htmlspecialchars($value) . '" />';
 	  }
 	}
     } else {
       // If hostname is not set we assume we are dealing with aggregate graphs
-      print "<input type=\"hidden\" name=\"host_name\" value=\"{$_GET['host_name']}\" />";
+      print "<input type=\"hidden\" name=\"host_name\" value=\"".htmlspecialchars($_GET['host_name'])."\" />";
       $metric_name=$_GET['metric_name'];
-      print "<input type=\"hidden\" name=\"metric_name\" value=\"{$_GET['metric_name']}\" />";
+      print "<input type=\"hidden\" name=\"metric_name\" value=\"".htmlspecialchars($_GET['metric_name'])."\" />";
       print "<input type=\"hidden\" name=\"type\" value=\"{$_GET['type']}\">";
       if (isset($_GET['vl']) && ($_GET['vl'] !== ''))
 	  print "<input type=\"hidden\" name=\"vertical_label\" value=\"" . htmlentities(stripslashes($_GET['vl'])) . "\" />";
```
