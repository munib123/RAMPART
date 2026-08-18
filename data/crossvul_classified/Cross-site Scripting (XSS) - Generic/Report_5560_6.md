# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5560_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5560_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-37 of the vulnerable file.

<?php
include_once "./eval_conf.php";
include_once("./functions.php");
include_once "./get_context.php";
include_once "./ganglia.php";
include_once "./get_ganglia.php";
?>
<?php
///////////////////////////////////////////////////////////////////////////////
// Generating mobile view
///////////////////////////////////////////////////////////////////////////////
if ( isset($_GET['view_name'])) {
?>  
  <div data-role="page" class="ganglia-mobile" id="view-home">
    <div data-role="header">
      <a href="#" class="ui-btn-left" data-icon="arrow-l" onclick="history.back(); return false">Back</a>
      <h1>View <?php print $_GET['view_name']; ?></h1>
      <a href="#mobile-home">Home</a>
      <div data-role="navbar">
	<ul>
  <?php

  $view_name = $_GET['view_name'];
  $available_views = get_available_views();
  
  // Header bar support up to 5 items. 5+ items will be shown in multiple
  // rows. Thus we'll limit to first 5 time ranges
  $my_ranges = array_keys( $conf['time_ranges'] );     
  for ( $i = 0 ; $i < 5 ; $i++ ) {
     $context_ranges[] = $my_ranges[$i]; 
  }

  $range_menu = "";
  $range = $_GET['r'];

  foreach ($context_ranges as $v) {
     $url=rawurlencode($v);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,7 +14,7 @@
   <div data-role="page" class="ganglia-mobile" id="view-home">
     <div data-role="header">
       <a href="#" class="ui-btn-left" data-icon="arrow-l" onclick="history.back(); return false">Back</a>
-      <h1>View <?php print $_GET['view_name']; ?></h1>
+      <h1>View <?php print htmlspecialchars($_GET['view_name']); ?></h1>
       <a href="#mobile-home">Home</a>
       <div data-role="navbar">
 	<ul>
@@ -39,7 +39,7 @@
       $checked = "class=\"ui-btn-active\"";
       $range_menu .= "<li><a $checked href='#' onclick='return false;'>$v</a></li>";
     } else {
-      $range_menu .= "<li><a href='mobile_helper.php?view_name=" . $_GET['view_name'] . "&r=" . $v . "&cs=&ce='>$v</a></li>";
+      $range_menu .= "<li><a href='mobile_helper.php?view_name=" . rawurlencode($_GET['view_name']) . "&r=" . $v . "&cs=&ce='>$v</a></li>";
     }
 
   }
@@ -61,9 +61,9 @@
 
       $range_args = "";
       if ( isset($_GET['r']) && $_GET['r'] != "" ) 
-	    $range_args .= "&r=" . $_GET['r'];
+	    $range_args .= "&r=" . rawurlencode($_GET['r']);
       if ( isset($_GET['cs']) && isset($_GET['ce']) ) 
-	    $range_args .= "&cs=" . $_GET['cs'] . "&ce=" . $_GET['ce'];
+	    $range_args .= "&cs=" . rawurlencode($_GET['cs']) . "&ce=" . rawurlencode($_GET['ce']);
 
       if ( count($view_elements) != 0 ) {
 	foreach ( $view_elements as $id => $element ) {
@@ -93,7 +93,7 @@
   <div data-role="page" class="ganglia-mobile" id="viewhost-<?php print $hostname; ?>">
     <div data-role="header" data-position="fixed">
       <a href="#" class="ui-btn-left" data-icon="arrow-l" onclick="history.back(); return false">Back</a>
-      <h3>Cluster <?php print $clustername; ?></h3>
+      <h3>Cluster <?php print htmlspecialchars($clustername); ?></h3>
       <a href="#mobile-home">Home</a>
         <div data-role="navbar">
 	<ul>
@@ -114,7 +114,7 @@
 	     $checked = "class=\"ui-btn-active\"";
       	     $range_menu .= "<li><a $checked href='#'>$v</a></li>";
 	  } else {
-      	     $range_menu .= "<li><a href='mobile_helper.php?show_cluster_metrics=1&c=" . $clustername . "&r=" . $v . "&cs=&ce='>$v</a></li>";
+      	     $range_menu .= "<li><a href='mobile_helper.php?show_cluster_metrics=1&c=" . rawurlencode($clustername) . "&r=" . $v . "&cs=&ce='>$v</a></li>";
 	  }
 	}
 	  print $range_menu;
@@ -125,7 +125,7 @@
   
     <div data-role="content">
 <?php
-    $graph_args = "c=$clustername&r=$range";
+    $graph_args = "c=".rawurlencode($clustername)."&r=".rawurlencode($range);
     
     ///////////////////////////////////////////////////////////////////////////
     // Let's find out what optional reports are included
@@ -137,7 +137,10 @@
       $default_reports = array_merge($default_reports,json_decode(file_get_contents($conf['conf_dir'] . "/default.json"), TRUE));
     }
     
-    $cluster_file = $conf['conf_dir'] . "/cluster_" . $clustername . ".json";
+    $cluster_file = $conf['conf_dir'] . "/cluster_" . preg_replace('/[^a-zA-Z0-9_-]/', '', $clustername) . ".json";
+    if ( pathinfo( $cluster_file, PATHINFO_DIRNAME ) != $conf['conf_dir'] ) {
+      die('Invalid path detected');
+    }
     $override_reports = array("included_reports" => array(), "excluded_reports" => array());
     if ( is_file($cluster_file) ) {
       $override_reports = array_merge($override_reports, json_decode(file_get_contents($cluster_file), TRUE));
@@ -154,8 +157,8 @@
     foreach ( $reports["included_reports"] as $index => $report_name ) {
       if ( ! in_array( $report_name, $reports["excluded_reports"] ) ) {
 	print "<a name=metric_" . $report_name . ">
-	<A HREF=\"./graph_all_periods.php?mobile=1&$graph_args&amp;g=" . $report_name . "&amp;z=mobile&amp;c=$clustername\">
-	<IMG BORDER=0 ALT=\"$clustername\" SRC=\"./graph.php?$graph_args&amp;g=" . $report_name ."&amp;z=mobile&amp;c=$clustername\"></A>
+	<A HREF=\"./graph_all_periods.php?mobile=1&$graph_args&amp;g=" . $report_name . "&amp;z=mobile&amp;c=".rawurlencode($clustername)."\">
+	<IMG BORDER=0 ALT=\"".rawurlencode($clustername)."\" SRC=\"./graph.php?$graph_args&amp;g=" . $report_name ."&amp;z=mobile&amp;c=".rawurlencode($clustername)."\"></A>
 	";
       }
 
@@ -173,10 +176,10 @@
   $hostname = $_GET['h'];
   $clustername = $_GET['c'];
 ?>
-  <div data-role="page" class="ganglia-mobile" id="viewhost-<?php print $hostname; ?>">
+  <div data-role="page" class="ganglia-mobile" id="viewhost-<?php print htmlspecialchars($hostname); ?>">
     <div data-role="header" data-position="fixed">
       <a href="#" class="ui-btn-left" data-icon="arrow-l" onclick="history.back(); return false">Back</a>
-      <h3>Host <?php print $hostname; ?></h3>
+      <h3>Host <?php print htmlspecialchars($hostname); ?></h3>
       <a href="#mobile-home">Home</a>
         <div data-role="navbar">
 	<ul>
@@ -197,7 +200,7 @@
 	     $checked = "class=\"ui-btn-active\"";
       	     $range_menu .= "<li><a $checked href='#'>$v</a></li>";
 	  } else {
-      	     $range_menu .= "<li><a href='mobile_helper.php?show_host_metrics=1&h=" . $hostname . "&c=" . $clustername . "&r=" . $v . "&cs=&ce='>$v</a></li>";
+      	     $range_menu .= "<li><a href='mobile_helper.php?show_host_metrics=1&h=" . rawurlencode($hostname) . "&c=" . rawurlencode($clustername) . "&r=" . $v . "&cs=&ce='>$v</a></li>";
 	  }
 	}
 	  print $range_menu;
@@ -208,7 +211,7 @@
   
     <div data-role="content">
 <?php
-    $graph_args = "h=$hostname&c=$clustername&r=$range";
+    $graph_args = "h=".rawurlencode($hostname)."&c=".rawurlencode($clustername)."&r=".rawurlencode($range);
     
     ///////////////////////////////////////////////////////////////////////////
     // Let's find out what optional reports are included
@@ -220,7 +223,10 @@
       $default_reports = array_merge($default_reports,json_decode(file_get_contents($conf['conf_dir'] . "/default.json"), TRUE));
     }
     
-    $host_file = $conf['conf_dir'] . "/host_" . $hostname . ".json";
+    $host_file = $conf['conf_dir'] . "/host_" . preg_replace('/[^a-zA-Z0-9_-]/', '', $hostname) . ".json";
+    if ( pathinfo( $host_file, PATHINFO_DIRNAME ) != $conf['conf_dir'] ) {
+      die('Invalid path detected');
+    }
     $override_reports = array("included_reports" => array(), "excluded_reports" => array());
     if ( is_file($host_file) ) {
       $override_reports = array_merge($override_reports, json_decode(file_get_contents($host_file), TRUE));
@@ -239,7 +245,7 @@
       if ( ! in_array( $report_name, $reports["excluded_reports"] ) ) {
 	print "
 	<A HREF=\"./graph_all_periods.php?mobile=1&$graph_args&amp;g=" . $report_name . "&amp;z=large\">
-	<IMG BORDER=0 ALT=\"$clustername\" SRC=\"./graph.php?$graph_args&amp;g=" . $report_name ."&amp;z=mobile\"></A>";
+	<IMG BORDER=0 ALT=\"".rawurlencode($clustername)."\" SRC=\"./graph.php?$graph_args&amp;g=" . $report_name ."&amp;z=mobile\"></A>";
       }
     }
     ?>  
@@ -260,8 +266,8 @@
   } else if (isset($reports[$metric_name]) and $reports[$metric])
     continue;
   else {
-    $metric_graphargs = "c=$clustername&amp;h=$hostname&amp;v=$metric_attributes[VAL]"
-      ."&amp;m=$metric_name&amp;r=$range&amp;z=$size&amp;jr=$jobrange"
+    $metric_graphargs = "c=".rawurlencode($clustername)."&amp;h=".rawurlencode($hostname)."&amp;v=".rawurlencode($metric_attributes[VAL])
+      ."&amp;m=$metric_name&amp;r=".rawurlencode($range)."&amp;z=$size&amp;jr=$jobrange"
       ."&amp;js=$jobstart&amp;st=$cluster[LOCALTIME]";
     if ($cs)
        $metric_graphargs .= "&amp;cs=" . rawurlencode($cs);
@@ -302,7 +308,7 @@
       foreach ( $metric_group_members as $index => $metric_name ) {
 	print "
 	<A HREF=\"./graph_all_periods.php?mobile=1&" . $g_metrics[$metric_name]['graph'] .  "\">
-	<IMG BORDER=0 ALT=\"$clustername\" SRC=\"./graph.php?" . $g_metrics[$metric_name]['graph'] . "\"></A>";
+	<IMG BORDER=0 ALT=\"".htmlspecialchars($clustername)."\" SRC=\"./graph.php?" . $g_metrics[$metric_name]['graph'] . "\"></A>";
       }
 ?>
... (diff truncated)
```
