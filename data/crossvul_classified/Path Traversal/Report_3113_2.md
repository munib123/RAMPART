# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3113_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3113_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 1-38 of the vulnerable file.

<?php
/**
 * This is b2evolution's application config file.
 *
 * @package conf
 */
if( !defined('EVO_CONFIG_LOADED') ) die( 'Please, do not access this page directly.' );


$app_name = 'b2evolution';
$app_shortname = 'b2evo';

/**
 * The version of the application.
 * Note: This has to be compatible with {@link http://us2.php.net/en/version-compare}.
 * @global string
 */
$app_version = '6.8.4-stable';

/**
 * Release date (ISO)
 * @global string
 */
$app_date = '2017-01-16';

/**
 * Long version string for checking differences
 */
$app_version_long = $app_version.'-'.$app_date;

/**
 * This is used to check if the database is up to date.
 *
 * This will be incrememented by 5 with each change in {@link upgrade_b2evo_tables()}
 * in order to leave space for maintenance releases.
 *
 * {@internal Before changing this in CVS, it should be discussed! }}
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,13 +15,13 @@
  * Note: This has to be compatible with {@link http://us2.php.net/en/version-compare}.
  * @global string
  */
-$app_version = '6.8.4-stable';
+$app_version = '6.8.5-stable';
 
 /**
  * Release date (ISO)
  * @global string
  */
-$app_date = '2017-01-16';
+$app_date = '2017-01-19';
 
 /**
  * Long version string for checking differences
@@ -36,7 +36,7 @@
  *
  * {@internal Before changing this in CVS, it should be discussed! }}
  */
-$new_db_version = 12140;
+$new_db_version = 12150;
 
 /**
  * Minimum PHP version required for b2evolution to function properly. It will contain each module own minimum PHP version as well.
```
