# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in php
**Pair ID:** 1190_1
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1190_1`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

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
$wp_version = '5.3-beta3-46471';

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
-$wp_version = '5.3-beta3-46471';
+$wp_version = '5.3-beta3-46472';
 
 /**
  * Holds the WordPress DB revision, increments when changes are made to the WordPress DB schema.
```
