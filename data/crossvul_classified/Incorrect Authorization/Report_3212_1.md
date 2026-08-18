# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 3212_1
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3212_1`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 1-27 of the vulnerable file.

<?php
/**
 * The WordPress version string
 *
 * @global string $wp_version
 */
$wp_version = '4.8-alpha-40160';

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
-$wp_version = '4.8-alpha-40160';
+$wp_version = '4.8-alpha-40169';
 
 /**
  * Holds the WordPress DB revision, increments when changes are made to the WordPress DB schema.
```
