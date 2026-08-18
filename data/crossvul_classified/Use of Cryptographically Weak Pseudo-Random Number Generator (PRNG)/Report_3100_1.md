# CrossVul Fix Pair: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) in php
**Pair ID:** 3100_1
**Vulnerability Class:** Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
**CWE:** CWE-338
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3100_1`)

## Vulnerability Information & PoC

## Description
Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) - When a non-cryptographic PRNG is used in a cryptographic context, it can expose the cryptography to certain types of attacks.

## Vulnerable Code
```php
Lines 1-27 of the vulnerable file.

<?php
/**
 * The WordPress version string
 *
 * @global string $wp_version
 */
$wp_version = '4.8-alpha-39772';

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
-$wp_version = '4.8-alpha-39772';
+$wp_version = '4.8-alpha-39795';
 
 /**
  * Holds the WordPress DB revision, increments when changes are made to the WordPress DB schema.
```
