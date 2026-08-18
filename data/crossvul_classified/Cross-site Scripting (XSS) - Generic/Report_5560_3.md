# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5560_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5560_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 6-46 of the vulnerable file.



if ( !isset($_GET['hreg']) or !isset($_GET['mreg']) ) {
    print '
	<div class="ui-widget">
			  <div class="ui-state-error ui-corner-all" style="padding: 0 .7em;"> 
				  <p><span class="ui-icon ui-icon-alert" style="float: left; margin-right: .3em;"></span> 
				  <strong>Alert:</strong> Host Regex and Metric Regex arguments are missing.</p>
			  </div>
	</div>
    ';

    exit(1);
}

$graph_type = "line";
$line_width = "2";
$graph_config = build_aggregate_graph_config ($graph_type, $line_width, $_GET['hreg'], $_GET['mreg']);

foreach ( $_GET['hreg'] as $index => $arg ) {
  print "<input type=hidden name=hreg[] value='" . $arg . "'>";
}
foreach ( $_GET['mreg'] as $index => $arg ) {
  print "<input type=hidden name=mreg[] value='" . $arg . "'>";
}

$size = isset($clustergraphsize) ? $clustergraphsize : 'default';
$size = $size == 'medium' ? 'default' : $size; //set to 'default' to preserve old behavior

$additional_host_img_css_classes = "";
if ( isset($conf['zoom_support']) && $conf['zoom_support'] === true )
    $additional_host_img_css_classes = "host_${size}_zoomable";

$data->assign("additional_host_img_css_classes", $additional_host_img_css_classes);

$items = array();

$graphargs = "";
if ($cs)
   $graphargs .= "&amp;cs=" . rawurlencode($cs);
if ($ce)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,10 +23,10 @@
 $graph_config = build_aggregate_graph_config ($graph_type, $line_width, $_GET['hreg'], $_GET['mreg']);
 
 foreach ( $_GET['hreg'] as $index => $arg ) {
-  print "<input type=hidden name=hreg[] value='" . $arg . "'>";
+  print "<input type=hidden name=hreg[] value='" . htmlspecialchars($arg) . "'>";
 }
 foreach ( $_GET['mreg'] as $index => $arg ) {
-  print "<input type=hidden name=mreg[] value='" . $arg . "'>";
+  print "<input type=hidden name=mreg[] value='" . htmlspecialchars($arg) . "'>";
 }
 
 $size = isset($clustergraphsize) ? $clustergraphsize : 'default';
```
