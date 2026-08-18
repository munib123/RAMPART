# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 232_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `232_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 622-662 of the vulnerable file.

            }
        }
        foreach ($newDir as $directory) {
 //           $directory = $this->smarty->_realpath($directory, true);
            $this->_resource_dir[ $directory ] = true;
        }
    }
    /**
     * Check if file is inside a valid directory
     *
     * @param string $filepath
     * @param array  $dirs valid directories
     *
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
            $directory = preg_replace('#[\\\\/][^\\\\/]+[\\\\/]$#', DIRECTORY_SEPARATOR, $directory);
        }
    }

    /**
     * Loads security class and enables security
     *
     * @param \Smarty                 $smarty
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -639,7 +639,8 @@
     {
         $directory = dirname($this->smarty->_realpath($filepath, true)) . DIRECTORY_SEPARATOR;
         $_directory = array();
-        while (true) {
+        if (!preg_match('#[\\\\/][.][.][\\\\/]#',$directory)) {
+            while (true) {
              // test if the directory is trusted
             if (isset($dirs[ $directory ])) {
                return $_directory;
@@ -647,13 +648,16 @@
             // abort if we've reached root
             if (!preg_match('#[\\\\/][^\\\\/]+[\\\\/]$#', $directory)) {
                 // give up
-                throw new SmartyException(sprintf('Smarty Security: not trusted file path \'%s\' ',$filepath));
+                break;
             }
             // remember the directory to add it to _resource_dir in case we're successful
             $_directory[ $directory ] = true;
            // bubble up one level
             $directory = preg_replace('#[\\\\/][^\\\\/]+[\\\\/]$#', DIRECTORY_SEPARATOR, $directory);
-        }
+            }
+        }
+        // give up
+        throw new SmartyException(sprintf('Smarty Security: not trusted file path \'%s\' ',$filepath));
     }
 
     /**
```
