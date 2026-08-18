# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 4928_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4928_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 1-37 of the vulnerable file.

<?php

/**
 * The autoloader used for loading sql-parser's components.
 *
 * This file is based on Composer's autoloader.
 *
 * (c) Nils Adermann <naderman@naderman.de>
 *     Jordi Boggiano <j.boggiano@seld.be>
 *
 * @package     SqlParser
 * @subpackage  Autoload
 */
namespace SqlParser\Autoload;

if (!class_exists('SqlParser\\Autoload\\ClassLoader')) {
    include_once './libraries/sql-parser/ClassLoader.php';
}

use SqlParser\Autoload\ClassLoader;

/**
 * Initializes the autoloader.
 *
 * @package     SqlParser
 * @subpackage  Autoload
 */
class AutoloaderInit
{

    /**
     * The loader instance.
     *
     * @var ClassLoader
     */
    public static $loader;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,6 +14,9 @@
 namespace SqlParser\Autoload;
 
 if (!class_exists('SqlParser\\Autoload\\ClassLoader')) {
+    if (! file_exists('./libraries/sql-parser/ClassLoader.php')) {
+        die('Invalid invocation');
+    }
     include_once './libraries/sql-parser/ClassLoader.php';
 }
 
```
