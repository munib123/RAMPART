# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in php
**Pair ID:** 1092_1
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1092_1`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

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
$wp_version = '5.3-alpha-45964';

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
$tinymce_version = '4940-20190515';

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
-$wp_version = '5.3-alpha-45964';
+$wp_version = '5.3-alpha-45971';
 
 /**
  * Holds the WordPress DB revision, increments when changes are made to the WordPress DB schema.
```
