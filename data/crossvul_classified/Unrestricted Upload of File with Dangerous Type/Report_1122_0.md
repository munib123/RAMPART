# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 1122_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1122_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 1-32 of the vulnerable file.

<?php
//Default Configuration
$CONFIG = '{"lang":"en","error_reporting":false,"show_hidden":false,"hide_Cols":false,"calc_folder":false}';

/**
 * H3K | Tiny File Manager V2.3.8
 * CCP Programmers | ccpprogrammers@gmail.com
 * https://tinyfilemanager.github.io
 */

//TFM version
define('VERSION', '2.3.8');

//Application Title
define('APP_TITLE', 'Tiny File Manager');

// Auth with login/password (set true/false to enable/disable it)
// Is independent from IP white- and blacklisting
$use_auth = true;

// Users: array('Username' => 'Password', 'Username2' => 'Password2', ...)
// Generate secure password hash - https://tinyfilemanager.github.io/docs/pwd.html
$auth_users = array(
    'admin' => '$2y$10$/K.hjNr84lLNDt8fTXjoI.DBp6PpeyoJ.mGwrrLuCZfAwfSAGqhOW', //admin@123
    'user' => '$2y$10$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp7avtQ9bDfrdRntXtPeiMAZyGO' //12345
);

// Readonly users (username array)
$readonly_users = array(
    'user'
);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,7 +9,7 @@
  */
 
 //TFM version
-define('VERSION', '2.3.8');
+define('VERSION', '2.3.9');
 
 //Application Title
 define('APP_TITLE', 'Tiny File Manager');
@@ -480,6 +480,12 @@
         }
 
         $err = false;
+        if(!fm_is_file_allowed($fileinfo->name)) {
+            $err = array("message" => "File extension is not allowed");
+            event_callback(array("fail" => $err));
+            exit();
+        }
+
         if (!$url) {
             $success = false;
         } else if ($use_curl) {
@@ -1921,6 +1927,27 @@
 // Functions
 
 /**
+ * Check if the filename is allowed.
+ * @param string $filename
+ * @return bool
+ */
+function fm_is_file_allowed($filename)
+{
+    // By default, no file is allowed
+    $allowed = false;
+
+    if (FM_EXTENSION) {
+        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
+
+        if (in_array($ext, explode(',', strtolower(FM_EXTENSION)))) {
+            $allowed = true;
+        }
+    }
+
+    return $allowed;
+}
+
+/**
  * Delete  file or folder (recursively)
  * @param string $path
  * @return bool
@@ -2215,7 +2242,8 @@
 
     // try a shell command
     if ($exec_works) {
-        $cmd = ($iswin) ? "for %F in (\"$file\") do @echo %~zF" : ($isdarwin ? "stat -f%z \"$file\"" : "stat -c%s \"$file\"");
+        $arg = escapeshellarg($file);
+        $cmd = ($iswin) ? "for %F in (\"$file\") do @echo %~zF" : ($isdarwin ? "stat -f%z $arg" : "stat -c%s $arg");
         @exec($cmd, $output);
         if (is_array($output) && ctype_digit($size = trim(implode("\n", $output)))) {
             return $size;
```
