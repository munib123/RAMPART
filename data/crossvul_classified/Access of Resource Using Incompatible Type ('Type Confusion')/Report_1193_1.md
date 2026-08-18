# CrossVul Fix Pair: Access of Resource Using Incompatible Type ('Type Confusion') in php
**Pair ID:** 1193_1
**Vulnerability Class:** Access of Resource Using Incompatible Type ('Type Confusion')
**CWE:** CWE-843
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1193_1`)

## Vulnerability Information & PoC

## Description
Access of Resource Using Incompatible Type ('Type Confusion') - When the product accesses the resource using an incompatible type, this could trigger logical errors because the resource does not have expected properties.

## Vulnerable Code
```php
Lines 1-36 of the vulnerable file.

<?php
/**
 * WordPress Version
 *
 * Contains version information for the current WordPress release.
 *
 * @package WordPress
 * @since 1.1.0
 */

/**
 * The WordPress version string
 *
 * @global string $wp_version
 */
$wp_version = '5.3-beta3-46476';

/**
 * Holds the WordPress DB revision, increments when changes are made to the WordPress DB schema.
 *
 * @global int $wp_db_version
 */
$wp_db_version = 45805;

/**
 * Holds the TinyMCE version
 *
 * @global string $tinymce_version
 */
$tinymce_version = '4960-20190918';

/**
 * Holds the required PHP version
 *
 * @global string $required_php_version
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,7 +13,7 @@
  *
  * @global string $wp_version
  */
-$wp_version = '5.3-beta3-46476';
+$wp_version = '5.3-beta3-46477';
 
 /**
  * Holds the WordPress DB revision, increments when changes are made to the WordPress DB schema.
```
