# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 229_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `229_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 635-675 of the vulnerable file.

     * @return array|bool
     * @throws \SmartyException
     */
    private function _checkDir($filepath, $dirs)
    {
        $directory = dirname($this->smarty->_realpath($filepath, true)) . DIRECTORY_SEPARATOR;
        $_directory = array();
        while (true) {
             // test if the directory is trusted
            if (isset($dirs[ $directory ])) {
               return $_directory;
            }
            // abort if we've reached root
            if (!preg_match('#[\\\\/][^\\\\/]+[\\\\/]$#', $directory)) {
                // give up
                throw new SmartyException(sprintf('Smarty Security: not trusted file path \'%s\' ',$filepath));
            }
            // remember the directory to add it to _resource_dir in case we're successful
            $_directory[ $directory ] = true;
           // bubble up one level
            $directory = preg_replace('#[\\\\/][^\\\\/]+[\\\\/]$#', '/', $directory);
        }
    }

    /**
     * Loads security class and enables security
     *
     * @param \Smarty                 $smarty
     * @param  string|Smarty_Security $security_class if a string is used, it must be class-name
     *
     * @return \Smarty current Smarty instance for chaining
     * @throws \SmartyException when an invalid class name is provided
     */
    public static function enableSecurity(Smarty $smarty, $security_class)
    {
        if ($security_class instanceof Smarty_Security) {
            $smarty->security_policy = $security_class;
            return $smarty;
        } elseif (is_object($security_class)) {
            throw new SmartyException("Class '" . get_class($security_class) . "' must extend Smarty_Security.");
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -652,7 +652,7 @@
             // remember the directory to add it to _resource_dir in case we're successful
             $_directory[ $directory ] = true;
            // bubble up one level
-            $directory = preg_replace('#[\\\\/][^\\\\/]+[\\\\/]$#', '/', $directory);
+            $directory = preg_replace('#[\\\\/][^\\\\/]+[\\\\/]$#', DIRECTORY_SEPARATOR, $directory);
         }
     }
 
```
