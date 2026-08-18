# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5560_9
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5560_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 15-55 of the vulnerable file.

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
                $_GET['view_name'] . 
                " already exists.";
    } else {
      $empty_view = array ("view_name" => $_GET['view_name'],
                           "items" => array());
      $view_suffix = str_replace(" ", "_", $_GET['view_name']);
      $view_filename = $conf['views_dir'] . "/view_" . $view_suffix . ".json";
      $json = json_encode($empty_view);
      if (file_put_contents($view_filename, 
                            json_prettyprint($json)) === FALSE) {
        $output = "<strong>Alert:</strong>" .
                  " Can't write to file $view_filename." .
                  " Perhaps permissions are wrong.";
      } else {
        $output = "View has been created successfully.";
      }
    }
  }
?>
<div class="ui-widget">
  <div class="ui-state-default ui-corner-all" style="padding: 0 .7em;"> 
    <p><span class="ui-icon ui-icon-alert" style="float: left; margin-right: .3em;"></span> 
    <?php echo $output ?></p>
  </div>
</div>
<?php
  exit(0);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,12 +32,15 @@
       $empty_view = array ("view_name" => $_GET['view_name'],
                            "items" => array());
       $view_suffix = str_replace(" ", "_", $_GET['view_name']);
-      $view_filename = $conf['views_dir'] . "/view_" . $view_suffix . ".json";
+      $view_filename = $conf['views_dir'] . "/view_" . preg_replace('/[^a-zA-Z0-9_-]/', '', $view_suffix) . ".json";
+      if ( pathinfo( $view_filename, PATHINFO_DIRNAME ) != $conf['views_dir'] ) {
+        die('Invalid path detected');
+      }
       $json = json_encode($empty_view);
       if (file_put_contents($view_filename, 
                             json_prettyprint($json)) === FALSE) {
         $output = "<strong>Alert:</strong>" .
-                  " Can't write to file $view_filename." .
+                  " Can't write to file " . htmlspecialchars($view_filename) .
                   " Perhaps permissions are wrong.";
       } else {
         $output = "View has been created successfully.";
@@ -79,7 +82,10 @@
       " does not exist.";
     } else {
       $view_suffix = str_replace(" ", "_", $_GET['view_name']);
-      $view_filename = $conf['views_dir'] . "/view_" . $view_suffix . ".json";
+      $view_filename = $conf['views_dir'] . "/view_" . preg_replace('/[^a-zA-Z0-9_-]/', '', $view_suffix) . ".json";
+      if ( pathinfo( $view_filename, PATHINFO_DIRNAME ) != $conf['views_dir'] ) {
+        die('Invalid path detected');
+      }
       if (unlink($view_filename) === FALSE) {
         $output = "<strong>Alert:</strong>" .
                   " Can't remove file $view_filename." .
```
