# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 230_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `230_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 497-546 of the vulnerable file.

    {
        if (isset($this->streams) && (empty($this->streams) || in_array($stream_name, $this->streams))) {
            return true;
        }

        throw new SmartyException("stream '{$stream_name}' not allowed by security setting");
    }

    /**
     * Check if directory of file resource is trusted.
     *
     * @param  string   $filepath
     * @param null|bool $isConfig
     *
     * @return bool true if directory is trusted
     * @throws \SmartyException if directory is not trusted
     */
    public function isTrustedResourceDir($filepath, $isConfig = null)
    {
        if ($this->_include_path_status !== $this->smarty->use_include_path) {
            foreach ($this->_include_dir as $directory) {
                unset($this->_resource_dir[ $directory ]);
            }
            if ($this->smarty->use_include_path) {
                $this->_include_dir = array();
                $_dirs = $this->smarty->ext->_getIncludePath->getIncludePathDirs($this->smarty);
                foreach ($_dirs as $directory) {
                    $this->_include_dir[] = $directory;
                    $this->_resource_dir[ $directory ] = true;
                }
            }
            $this->_include_path_status = $this->smarty->use_include_path;
        }
        if ($isConfig !== true &&
            (!isset($this->smarty->_cache[ 'template_dir_new' ]) || $this->smarty->_cache[ 'template_dir_new' ])
        ) {
            $_dir = $this->smarty->getTemplateDir();
            if ($this->_template_dir !== $_dir) {
                foreach ($this->_template_dir as $directory) {
                    unset($this->_resource_dir[ $directory ]);
                }
                foreach ($_dir as $directory) {
                    $this->_resource_dir[ $directory ] = true;
                }
                $this->_template_dir = $_dir;
            }
            $this->smarty->_cache[ 'template_dir_new' ] = false;
        }
        if ($isConfig !== false &&
            (!isset($this->smarty->_cache[ 'config_dir_new' ]) || $this->smarty->_cache[ 'config_dir_new' ])
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -514,60 +514,39 @@
     public function isTrustedResourceDir($filepath, $isConfig = null)
     {
         if ($this->_include_path_status !== $this->smarty->use_include_path) {
-            foreach ($this->_include_dir as $directory) {
-                unset($this->_resource_dir[ $directory ]);
-            }
-            if ($this->smarty->use_include_path) {
-                $this->_include_dir = array();
-                $_dirs = $this->smarty->ext->_getIncludePath->getIncludePathDirs($this->smarty);
-                foreach ($_dirs as $directory) {
-                    $this->_include_dir[] = $directory;
-                    $this->_resource_dir[ $directory ] = true;
-                }
+            $_dir = $this->smarty->use_include_path ? $this->smarty->ext->_getIncludePath->getIncludePathDirs($this->smarty) : array();
+            if ($this->_include_dir !== $_dir) {
+                $this->_updateResourceDir($this->_include_dir, $_dir);
+                $this->_include_dir = $_dir;
             }
             $this->_include_path_status = $this->smarty->use_include_path;
         }
-        if ($isConfig !== true &&
-            (!isset($this->smarty->_cache[ 'template_dir_new' ]) || $this->smarty->_cache[ 'template_dir_new' ])
-        ) {
+        if ($isConfig !== true) {
             $_dir = $this->smarty->getTemplateDir();
             if ($this->_template_dir !== $_dir) {
-                foreach ($this->_template_dir as $directory) {
-                    unset($this->_resource_dir[ $directory ]);
-                }
-                foreach ($_dir as $directory) {
-                    $this->_resource_dir[ $directory ] = true;
-                }
+                $this->_updateResourceDir($this->_template_dir, $_dir);
                 $this->_template_dir = $_dir;
             }
-            $this->smarty->_cache[ 'template_dir_new' ] = false;
-        }
-        if ($isConfig !== false &&
-            (!isset($this->smarty->_cache[ 'config_dir_new' ]) || $this->smarty->_cache[ 'config_dir_new' ])
-        ) {
+        }
+        if ($isConfig !== false) {
             $_dir = $this->smarty->getConfigDir();
             if ($this->_config_dir !== $_dir) {
-                foreach ($this->_config_dir as $directory) {
-                    unset($this->_resource_dir[ $directory ]);
-                }
-                foreach ($_dir as $directory) {
-                    $this->_resource_dir[ $directory ] = true;
-                }
+                $this->_updateResourceDir($this->_config_dir, $_dir);
                 $this->_config_dir = $_dir;
             }
-            $this->smarty->_cache[ 'config_dir_new' ] = false;
-        }
-        if ($this->_secure_dir !== (array) $this->secure_dir) {
-            foreach ($this->_secure_dir as $directory) {
-                unset($this->_resource_dir[ $directory ]);
-            }
-            foreach ((array) $this->secure_dir as $directory) {
-                $directory = $this->smarty->_realpath($directory . DIRECTORY_SEPARATOR, true);
-                $this->_resource_dir[ $directory ] = true;
-            }
-            $this->_secure_dir = (array) $this->secure_dir;
-        }
-        $this->_resource_dir = $this->_checkDir($filepath, $this->_resource_dir);
+        }
+        if ($this->_secure_dir !== $this->secure_dir) {
+            $this->secure_dir = (array)$this->secure_dir;
+            foreach($this->secure_dir as $k => $d) {
+                $this->secure_dir[$k] = $this->smarty->_realpath($d.DIRECTORY_SEPARATOR,true);
+            }
+            $this->_updateResourceDir($this->_secure_dir, $this->secure_dir);
+            $this->_secure_dir = $this->secure_dir;
+        }
+        $addPath =  $this->_checkDir($filepath, $this->_resource_dir);
+        if ($addPath !== false) {
+           $this->_resource_dir = array_merge($this->_resource_dir, $addPath);
+        }
         return true;
     }
 
@@ -622,40 +601,64 @@
                 $this->_php_resource_dir[ $directory ] = true;
             }
         }
-
-        $this->_php_resource_dir =
-            $this->_checkDir($this->smarty->_realpath($filepath, true), $this->_php_resource_dir);
-        return true;
-    }
-
+        $addPath =  $this->_checkDir($filepath, $this->_php_resource_dir);
+        if ($addPath !== false) {
+           $this->_php_resource_dir = array_merge($this->_php_resource_dir, $addPath);
+        }
+         return true;
+    }
+
+    /**
+     * Remove old directories and its sub folders, add new directories
+     *
+     * @param array $oldDir
+     * @param array $newDir
+     */
+    private function _updateResourceDir($oldDir, $newDir) {
+        foreach ($oldDir as $directory) {
+            $directory = $this->smarty->_realpath($directory, true);
+            $length = strlen($directory);
+            foreach ($this->_resource_dir as $dir) {
+                if (substr($dir, 0,$length) === $directory) {
+                    unset($this->_resource_dir[ $dir ]);
+                }
+            }
+        }
+        foreach ($newDir as $directory) {
+            $directory = $this->smarty->_realpath($directory, true);
+            $this->_resource_dir[ $directory ] = true;
+        }
+    }
     /**
      * Check if file is inside a valid directory
      *
      * @param string $filepath
      * @param array  $dirs valid directories
      *
-     * @return array
+     * @return array|bool
      * @throws \SmartyException
      */
     private function _checkDir($filepath, $dirs)
     {
+        $directory = dirname($filepath) . DIRECTORY_SEPARATOR;
+        if (isset($dirs[ $directory ])) {
+            return false;
+        }
+        $filepath = $this->smarty->_realpath($filepath, true);
         $directory = dirname($filepath) . DIRECTORY_SEPARATOR;
         $_directory = array();
         while (true) {
-            // remember the directory to add it to _resource_dir in case we're successful
-            $_directory[ $directory ] = true;
-            // test if the directory is trusted
+             // test if the directory is trusted
             if (isset($dirs[ $directory ])) {
-                // merge sub directories of current $directory into _resource_dir to speed up subsequent lookup
-                $dirs = array_merge($dirs, $_directory);
-
-                return $dirs;
+               return $_directory;
             }
             // abort if we've reached root
             if (!preg_match('#[\\\/][^\\\/]+[\\\/]$#', $directory)) {
                 break;
             }
-            // bubble up one level
+            // remember the directory to add it to _resource_dir in case we're successful
+            $_directory[ $directory ] = true;
+           // bubble up one level
             $directory = preg_replace('#[\\\/][^\\\/]+[\\\/]$#', DIRECTORY_SEPARATOR, $directory);
         }
 
```
