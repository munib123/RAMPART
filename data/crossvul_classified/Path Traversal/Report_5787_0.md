# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 5787_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5787_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 1479-1519 of the vulnerable file.


            unlink($filename);
            return array('success' => "$id was deleted!");
        } else {

            $filename = $here . $id . '.sql';
            if (is_file($filename)) {
                unlink($filename);
                return array('success' => "$id was deleted!");
            }
        }

        //d($filename);
    }

    function download($params)
    {
        if (!is_admin()) {
            error("must be admin");
        }
        ;
        ini_set('memory_limit', '512M');
        set_time_limit(0);

        if (isset($params['id'])) {
            $id = $params['id'];
        } else if (isset($_GET['filename'])) {
            $id = $params['filename'];
        } else if (isset($_GET['file'])) {
            $id = $params['file'];
        }

        // Check if the file has needed args
        if ($id == NULL) {
            return array('error' => "You have not provided filename to download.");

            die();
        }

        $here = $this->get_bakup_location();
        // Generate filename and set error variables
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1496,7 +1496,7 @@
         if (!is_admin()) {
             error("must be admin");
         }
-        ;
+
         ini_set('memory_limit', '512M');
         set_time_limit(0);
 
@@ -1507,6 +1507,8 @@
         } else if (isset($_GET['file'])) {
             $id = $params['file'];
         }
+        $id = str_replace('..', '', $id);
+
 
         // Check if the file has needed args
         if ($id == NULL) {
@@ -1519,6 +1521,7 @@
         // Generate filename and set error variables
 
         $filename = $here . $id;
+        $filename = str_replace('..','',$filename);
         if (!is_file($filename)) {
             return array('error' => "You have not provided a existising filename to download.");
 
@@ -1542,6 +1545,10 @@
 
     function readfile_chunked($filename, $retbytes = TRUE)
     {
+
+
+        $filename = str_replace('..','',$filename);
+
         $chunk_size = 1024 * 1024;
         $buffer = "";
         $cnt = 0;
@@ -1550,6 +1557,10 @@
         if ($handle === false) {
             return false;
         }
+
+
+
+
         while (!feof($handle)) {
             $buffer = fread($handle, $chunk_size);
             echo $buffer;
```
