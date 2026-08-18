# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5560_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5560_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 36-76 of the vulnerable file.

    initTimeShift();
<?php if ( isset($_GET['embed'] ) ) { ?>
    initMetricActionsDialog();
<?php } ?>
<?php if ( ! isset($_REQUEST['mobile'])) { ?>
    $( "#popup-dialog" ).dialog({ autoOpen: false, minWidth: 850 });
<?php } ?>
  });
</script>

<?php
include_once "./eval_conf.php";
include_once "./global.php";

// build a query string but drop r and z since those designate time window and size. Also if the 
// get arguments are an array rebuild them. For example with hreg (host regex)
$ignore_keys_list = array("r", "z", "st", "cs", "ce", "hc");

foreach ($_GET as $key => $value) {
  if ( ! in_array($key, $ignore_keys_list) && ! is_array($value))
    $query_string_array[] = "$key=" . urlencode($value);

  // $_GET argument is an array. Rebuild it to pass it on
  if ( is_array($value) ) {
    foreach ( $value as $index => $value2 )
      $query_string_array[] = $key . "[]=" . urlencode($value2);

  }
}

// If we are in the mobile mode set the proper graph sizes
if ( isset($_GET['mobile'])) {
  $largesize = "mobile";
  $xlargesize = "mobile";
} else {
  $largesize = "large";
  $xlargesize = "xlarge";  
}

// Join all the query_string arguments
$query_string = "&amp;" . join("&amp;", $query_string_array);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,12 +53,12 @@
 
 foreach ($_GET as $key => $value) {
   if ( ! in_array($key, $ignore_keys_list) && ! is_array($value))
-    $query_string_array[] = "$key=" . urlencode($value);
+    $query_string_array[] = rawurlencode($key) . "=" . urlencode($value);
 
   // $_GET argument is an array. Rebuild it to pass it on
   if ( is_array($value) ) {
     foreach ( $value as $index => $value2 )
-      $query_string_array[] = $key . "[]=" . urlencode($value2);
+      $query_string_array[] = rawurlencode($key) . "[]=" . urlencode($value2);
 
   }
 }
@@ -77,20 +77,20 @@
 
 // Descriptive host/aggregate graph
 if (isset($_GET['h']) && ($_GET['h'] != ''))
-  $description = $_GET['h'];
+  $description = htmlspecialchars($_GET['h']);
 else if (isset($_GET['c']) && ($_GET['c'] != ''))
-  $description = $_GET['c'];
+  $description = htmlspecialchars($_GET['c']);
 else if (is_array($_GET['hreg']))
-  $description = join(",", $_GET['hreg']);
+  $description = htmlspecialchars( join(",", $_GET['hreg']) );
 else
   $description = "Unknown";
 
 if (isset($_GET['g'])) 
-  $metric_description = $_GET['g'];
+  $metric_description = htmlspecialchars($_GET['g']);
 else if ( isset($_GET['m'] ))
-  $metric_description = $_GET['m'];
+  $metric_description = htmlspecialchars($_GET['m']);
 else if (is_array($_GET['mreg']) )
-  $metric_description = join(",", $_GET['mreg']);
+  $metric_description = htmlspecialchars( join(",", $_GET['mreg']) );
 else
   $metric_description = "Unknown";
 
@@ -152,7 +152,7 @@
     <div data-role="page" class="ganglia-mobile" id="view-home">
     <div data-role="header">
       <a href="#" class="ui-btn-left" data-icon="arrow-l" onclick="history.back(); return false">Back</a>
-      <h3><?php if (isset($_GET['g'])) echo $_GET['g']; else echo $_GET['m']; ?></h3>
+      <h3><?php if (isset($_GET['g'])) echo htmlspecialchars($_GET['g']); else echo htmlspecialchars($_GET['m']); ?></h3>
       <a href="#mobile-home">Home</a>
     </div>
     <div data-role="content">
```
