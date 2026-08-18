# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5218_2
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5218_2`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-27 of the vulnerable file.

<?php
/**
 * The WordPress version string
 *
 * @global string $wp_version
 */
$wp_version = '4.5-RC1-37135';

/**
 * Holds the WordPress DB revision, increments when changes are made to the WordPress DB schema.
 *
 * @global int $wp_db_version
 */
$wp_db_version = 36686;

/**
 * Holds the TinyMCE version
 *
 * @global string $tinymce_version
 */
$tinymce_version = '4308-20160323';

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
-$wp_version = '4.5-RC1-37135';
+$wp_version = '4.5-RC1-37143';
 
 /**
  * Holds the WordPress DB revision, increments when changes are made to the WordPress DB schema.
```
