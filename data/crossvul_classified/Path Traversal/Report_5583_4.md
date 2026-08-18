# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 5583_4
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5583_4`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 1-37 of the vulnerable file.

<?php

/**
  @returns the FullPath out of an RelativePath

  A FullPath is the full path including the home directory and a subdirectory
  below of it.

  If the home directory is set to '/var/www/data' in the conf.php ('home_dir'),
  and you provide a RelativePath of 'first_subdirectory', the function returns
  '/var/www/data/first_subdirectory'.

  This path is intended for internal use and not for presentation to the
  user, since he should only see relative pathes.
 
 */
function path_f ($path)
{
    global $home_dir;
    $abs_dir = $home_dir;
    switch ($path)
    {
        case '.':
        case '': return realpath($abs_dir);
    }
    
    return realpath(realpath($home_dir) . "/$path");
}

function path_r ($path)
{
    global $home_dir;
    $base = realpath($home_dir);
    $ret = preg_replace("#^$base#", "", $path);
    return $ret;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,7 +14,7 @@
   user, since he should only see relative pathes.
  
  */
-function path_f ($path)
+function path_f ($path = '')
 {
     global $home_dir;
     $abs_dir = $home_dir;
```
