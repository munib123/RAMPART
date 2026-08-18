# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5560_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5560_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 39-79 of the vulnerable file.

         ! isset($host_metrics[$metric_name]) ) {
      $host_metrics[$metric_name] = 1; 
    }
  }
}

# Join the hosts in a list into a string which we pass to graphs
$host_list = join(",", $host_cluster);

ksort($host_metrics);
#print "<PRE>";print_r($host_metrics);

$hmetrics = array();
foreach ( $host_metrics as $name => $value )
  $hmetrics[] = $name;


$hreg = "";
if (array_key_exists('hreg', $_GET)) {
  foreach ( $_GET['hreg'] as $index => $arg ) {
    $hreg .= "&hreg[]=" . $arg;
  }
}

if ( isset($_GET['hreg']) ) {
  $data->assign("hreg_arg", $_GET['hreg'][0]);
} else {
  $data->assign("hreg_arg", "");
}

$size = isset($clustergraphsize) ? $clustergraphsize : 'default';
//set to 'default' to preserve old behavior
$size = $size == 'medium' ? 'default' : $size; 

$additional_host_img_css_classes = "";
if ( isset($conf['zoom_support']) && $conf['zoom_support'] === true )
    $additional_host_img_css_classes = "host_${size}_zoomable";

$data->assign("additional_host_img_css_classes", $additional_host_img_css_classes);

$graphargs = "&r=" . $range;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,12 +56,12 @@
 $hreg = "";
 if (array_key_exists('hreg', $_GET)) {
   foreach ( $_GET['hreg'] as $index => $arg ) {
-    $hreg .= "&hreg[]=" . $arg;
+    $hreg .= "&hreg[]=" . rawurlencode($arg);
   }
 }
 
 if ( isset($_GET['hreg']) ) {
-  $data->assign("hreg_arg", $_GET['hreg'][0]);
+  $data->assign("hreg_arg", htmlspecialchars($_GET['hreg'][0]) );
 } else {
   $data->assign("hreg_arg", "");
 }
```
