# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 233_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `233_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 241-282 of the vulnerable file.

    /**
     * Cache for include path status
     *
     * @var bool
     */
    protected $_include_path_status = false;

    /**
     * Cache for $_include_array lookup
     *
     * @var array
     */
    protected $_include_dir = array();

    /**
     * @param Smarty $smarty
     */
    public function __construct($smarty)
    {
        $this->smarty = $smarty;
        $this->smarty->_cache[ 'template_dir_new' ] = true;
        $this->smarty->_cache[ 'config_dir_new' ] = true;
    }

    /**
     * Check if PHP function is trusted.
     *
     * @param  string $function_name
     * @param  object $compiler compiler object
     *
     * @return boolean                 true if function is trusted
     * @throws SmartyCompilerException if php function is not trusted
     */
    public function isTrustedPhpFunction($function_name, $compiler)
    {
        if (isset($this->php_functions) &&
            (empty($this->php_functions) || in_array($function_name, $this->php_functions))
        ) {
            return true;
        }

        $compiler->trigger_template_error("PHP function '{$function_name}' not allowed by security setting");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -258,8 +258,6 @@
     public function __construct($smarty)
     {
         $this->smarty = $smarty;
-        $this->smarty->_cache[ 'template_dir_new' ] = true;
-        $this->smarty->_cache[ 'config_dir_new' ] = true;
     }
 
     /**
@@ -521,24 +519,23 @@
             }
             $this->_include_path_status = $this->smarty->use_include_path;
         }
-        if ($isConfig !== true) {
+
             $_dir = $this->smarty->getTemplateDir();
             if ($this->_template_dir !== $_dir) {
                 $this->_updateResourceDir($this->_template_dir, $_dir);
                 $this->_template_dir = $_dir;
             }
-        }
-        if ($isConfig !== false) {
+
             $_dir = $this->smarty->getConfigDir();
             if ($this->_config_dir !== $_dir) {
                 $this->_updateResourceDir($this->_config_dir, $_dir);
                 $this->_config_dir = $_dir;
             }
-        }
+
         if ($this->_secure_dir !== $this->secure_dir) {
             $this->secure_dir = (array)$this->secure_dir;
             foreach($this->secure_dir as $k => $d) {
-                $this->secure_dir[$k] = $this->smarty->_realpath($d.DIRECTORY_SEPARATOR,true);
+                $this->secure_dir[$k] = $this->smarty->_realpath($d. DIRECTORY_SEPARATOR,true);
             }
             $this->_updateResourceDir($this->_secure_dir, $this->secure_dir);
             $this->_secure_dir = $this->secure_dir;
@@ -597,7 +594,7 @@
 
             $this->_trusted_dir = $this->trusted_dir;
             foreach ((array) $this->trusted_dir as $directory) {
-                $directory = $this->smarty->_realpath($directory . DIRECTORY_SEPARATOR, true);
+                $directory = $this->smarty->_realpath($directory . '/', true);
                 $this->_php_resource_dir[ $directory ] = true;
             }
         }
@@ -616,7 +613,7 @@
      */
     private function _updateResourceDir($oldDir, $newDir) {
         foreach ($oldDir as $directory) {
-            $directory = $this->smarty->_realpath($directory, true);
+ //           $directory = $this->smarty->_realpath($directory, true);
             $length = strlen($directory);
             foreach ($this->_resource_dir as $dir) {
                 if (substr($dir, 0,$length) === $directory) {
@@ -625,7 +622,7 @@
             }
         }
         foreach ($newDir as $directory) {
-            $directory = $this->smarty->_realpath($directory, true);
+ //           $directory = $this->smarty->_realpath($directory, true);
             $this->_resource_dir[ $directory ] = true;
         }
     }
@@ -640,12 +637,7 @@
      */
     private function _checkDir($filepath, $dirs)
     {
-        $directory = dirname($filepath) . DIRECTORY_SEPARATOR;
-        if (isset($dirs[ $directory ])) {
-            return false;
-        }
-        $filepath = $this->smarty->_realpath($filepath, true);
-        $directory = dirname($filepath) . DIRECTORY_SEPARATOR;
+        $directory = dirname($this->smarty->_realpath($filepath, true)) . DIRECTORY_SEPARATOR;
         $_directory = array();
         while (true) {
              // test if the directory is trusted
@@ -653,17 +645,15 @@
                return $_directory;
             }
             // abort if we've reached root
-            if (!preg_match('#[\\\/][^\\\/]+[\\\/]$#', $directory)) {
-                break;
+            if (!preg_match('#[\\\\/][^\\\\/]+[\\\\/]$#', $directory)) {
+                // give up
+                throw new SmartyException(sprintf('Smarty Security: not trusted file path \'%s\' ',$filepath));
             }
             // remember the directory to add it to _resource_dir in case we're successful
             $_directory[ $directory ] = true;
            // bubble up one level
-            $directory = preg_replace('#[\\\/][^\\\/]+[\\\/]$#', DIRECTORY_SEPARATOR, $directory);
-        }
-
-        // give up
-        throw new SmartyException("directory '{$filepath}' not allowed by security setting");
+            $directory = preg_replace('#[\\\\/][^\\\\/]+[\\\\/]$#', '/', $directory);
+        }
     }
 
     /**
```
