# CrossVul Fix Pair: Initialization of a Resource with an Insecure Default in php
**Pair ID:** 3098_0
**Vulnerability Class:** Misconfiguration
**CWE:** CWE-1188
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3098_0`)

## Vulnerability Information & PoC

## Description
Initialization of a Resource with an Insecure Default - Developers often choose default values that leave the product as open and easy to use as possible out-of-the-box, under the assumption that the administrator can (or should) change the default value.

## Vulnerable Code
```php
Lines 1-27 of the vulnerable file.

<?php
/**
 * The WordPress version string
 *
 * @global string $wp_version
 */
$wp_version = '4.8-alpha-39760';

/**
 * Holds the WordPress DB revision, increments when changes are made to the WordPress DB schema.
 *
 * @global int $wp_db_version
 */
$wp_db_version = 38590;

/**
 * Holds the TinyMCE version
 *
 * @global string $tinymce_version
 */
$tinymce_version = '4403-20160901';

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
@@ -4,7 +4,7 @@
  *
  * @global string $wp_version
  */
-$wp_version = '4.8-alpha-39760';
+$wp_version = '4.8-alpha-39772';
 
 /**
  * Holds the WordPress DB revision, increments when changes are made to the WordPress DB schema.
```
