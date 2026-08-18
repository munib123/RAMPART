# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 3734_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3734_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 1-23 of the vulnerable file.

<?php
/* vim: set expandtab sw=4 ts=4 sts=4: */
/**
 * Simple wrapper just to enable error reporting and include config
 *
 * @package PhpMyAdmin
 */

$GLOBALS['now'] = gmdate('D, d M Y H:i:s') . ' GMT';
PMA_no_cache_header();
header('Content-Type: text/html; charset=utf-8');

require './libraries/vendor_config.php';

error_reporting(E_ALL);
/**
 * Read config file.
 */
if (is_readable(CONFIG_FILE)) {
    require CONFIG_FILE;
}

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,10 @@
  *
  * @package PhpMyAdmin
  */
+
+// we need the common loader for the PMA_no_cache_header function
+define('PMA_MINIMUM_COMMON', 1);
+require './libraries/common.inc.php';
 
 $GLOBALS['now'] = gmdate('D, d M Y H:i:s') . ' GMT';
 PMA_no_cache_header();
```
