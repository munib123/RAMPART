# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 4002_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4002_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 147-187 of the vulnerable file.

    }

    /**
     * Load the specified plugin
     *
     * @param string  Plugin name
     * @param boolean Force loading of the plugin even if it doesn't match the filter
     * @param boolean Require loading of the plugin, error if it doesn't exist
     *
     * @return boolean True on success, false if not loaded or failure
     */
    public function load_plugin($plugin_name, $force = false, $require = true)
    {
        static $plugins_dir;

        if (!$plugins_dir) {
            $dir         = dir($this->dir);
            $plugins_dir = unslashify($dir->path);
        }

        // plugin already loaded?
        if (!$this->plugins[$plugin_name]) {
            $fn = "$plugins_dir/$plugin_name/$plugin_name.php";

            if (!is_readable($fn)) {
                if ($require) {
                    rcube::raise_error(array('code' => 520, 'type' => 'php',
                        'file' => __FILE__, 'line' => __LINE__,
                        'message' => "Failed to load plugin file $fn"), true, false);
                }

                return false;
            }

            if (!class_exists($plugin_name, false)) {
                include $fn;
            }

            // instantiate class if exists
            if (!class_exists($plugin_name, false)) {
                rcube::raise_error(array('code' => 520, 'type' => 'php',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -162,6 +162,14 @@
         if (!$plugins_dir) {
             $dir         = dir($this->dir);
             $plugins_dir = unslashify($dir->path);
+        }
+
+        // Validate the plugin name to prevent from path traversal
+        if (preg_match('/[^a-zA-Z0-9_-]/', $plugin_name)) {
+            rcube::raise_error(array('code' => 520,
+                    'file' => __FILE__, 'line' => __LINE__,
+                    'message' => "Invalid plugin name: $plugin_name"), true, false);
+            return false;
         }
 
         // plugin already loaded?
@@ -283,6 +291,14 @@
         $fn   = unslashify($dir->path) . "/$plugin_name/$plugin_name.php";
         $info = false;
 
+        // Validate the plugin name to prevent from path traversal
+        if (preg_match('/[^a-zA-Z0-9_-]/', $plugin_name)) {
+            rcube::raise_error(array('code' => 520,
+                    'file' => __FILE__, 'line' => __LINE__,
+                    'message' => "Invalid plugin name: $plugin_name"), true, false);
+            return false;
+        }
+
         if (!class_exists($plugin_name, false)) {
             if (is_readable($fn)) {
                 include($fn);
```
