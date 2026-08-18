# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5560_7
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5560_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-33 of the vulnerable file.

<?php
$months_ahead = array(0,1,2,3,6,9,12,18,24);
$months_back = array(12,9,6,3,2,1);
if ( !isset($_REQUEST['trendrange']) )
  $_REQUEST['trendrange'] = 6;
if ( !isset($_REQUEST['trendhistory']) )
  $_REQUEST['trendhistory'] = 6;

$drop_args = array("trendrange", "trendhistory");

foreach ( $_REQUEST as $key => $value ) {
  if ( ! in_array($key, $drop_args) )
    $graph_args[] = $key . "=" . str_replace("_/graph_php?", "", $value);
}

$query_string = preg_replace("/(&trendrange=)(\d+)/", "", $_SERVER['QUERY_STRING'] );
$query_string = preg_replace("/(&trendhistory=)(\d+)/", "", $query_string);


?>
<center>
<div id="trend_range_menu">
<form id="trend_range_form">
Use data from last 
<?php
foreach ( $months_back as $index => $month ) {
  if (  $_REQUEST['trendhistory'] == $month )
    $checked = 'checked="checked"';
  else
    $checked = "";
?>
   <input OnChange='drawTrendGraph("<?php print $query_string ?>" + "&" + $("#trend_range_form").serialize()); return false;' type="radio" id="trendhistory-<?php print $month; ?>" name="trendhistory" value="<?php print $month; ?>" <?php print $checked; ?>/>
   <label for="trendhistory-<?php print $month; ?>"><?php print $month; ?></label>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,11 +10,11 @@
 
 foreach ( $_REQUEST as $key => $value ) {
   if ( ! in_array($key, $drop_args) )
-    $graph_args[] = $key . "=" . str_replace("_/graph_php?", "", $value);
+    $graph_args[] = rawurlencode($key) . "=" . rawurlencode( str_replace("_/graph_php?", "", $value) );
 }
 
 $query_string = preg_replace("/(&trendrange=)(\d+)/", "", $_SERVER['QUERY_STRING'] );
-$query_string = preg_replace("/(&trendhistory=)(\d+)/", "", $query_string);
+$query_string = preg_replace("/(&trendhistory=)(\d+)/", "", htmlspecialchars($query_string, ENT_QUOTES) );
 
 
 ?>
```
