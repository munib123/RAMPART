# CrossVul Fix Pair: Use of Insufficiently Random Values in php
**Pair ID:** 2960_1
**Vulnerability Class:** Use of Insufficiently Random Values
**CWE:** CWE-330
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2960_1`)

## Vulnerability Information & PoC

## Description
Use of Insufficiently Random Values - When product generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated, and use this guess to impersona...

## Vulnerable Code
```php
Lines 1-27 of the vulnerable file.

<?php
/**
 * The WordPress version string
 *
 * @global string $wp_version
 */
$wp_version = '5.0-alpha-42257';

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
$tinymce_version = '4607-20171116';

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
-$wp_version = '5.0-alpha-42257';
+$wp_version = '5.0-alpha-42258';
 
 /**
  * Holds the WordPress DB revision, increments when changes are made to the WordPress DB schema.
```
