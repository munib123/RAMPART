# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 877_6
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `877_6`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 43-87 of the vulnerable file.


define('PATH_UPLOADS_PAGES',		PATH_UPLOADS.'pages'.DS);
define('PATH_UPLOADS_PROFILES',		PATH_UPLOADS.'profiles'.DS);
define('PATH_UPLOADS_THUMBNAILS',	PATH_UPLOADS.'thumbnails'.DS);

define('PATH_ADMIN',			PATH_KERNEL.'admin'.DS);
define('PATH_ADMIN_THEMES',		PATH_ADMIN.'themes'.DS);
define('PATH_ADMIN_CONTROLLERS',	PATH_ADMIN.'controllers'.DS);
define('PATH_ADMIN_VIEWS',		PATH_ADMIN.'views'.DS);

define('DEBUG_FILE',			PATH_CONTENT.'debug.txt');

// PAGES DATABASE
define('DB_PAGES', PATH_DATABASES.'pages.php');
define('DB_SITE', PATH_DATABASES.'site.php');
define('DB_CATEGORIES', PATH_DATABASES.'categories.php');
define('DB_TAGS', PATH_DATABASES.'tags.php');
define('DB_SYSLOG', PATH_DATABASES.'syslog.php');
define('DB_USERS', PATH_DATABASES.'users.php');
define('DB_SECURITY', PATH_DATABASES.'security.php');

// JSON pretty print
if (!defined('JSON_PRETTY_PRINT')) {
	define('JSON_PRETTY_PRINT', 128);
}

// User environment variables
include(PATH_KERNEL.'boot'.DS.'variables.php');

// Set internal character encoding
mb_internal_encoding(CHARSET);

// Set HTTP output character encoding
mb_http_output(CHARSET);

// Inclde Abstract Classes
include(PATH_ABSTRACT.'dbjson.class.php');
include(PATH_ABSTRACT.'dblist.class.php');
include(PATH_ABSTRACT.'plugin.class.php');

// Inclde Classes
include(PATH_KERNEL.'pages.class.php');
include(PATH_KERNEL.'users.class.php');
include(PATH_KERNEL.'tags.class.php');
include(PATH_KERNEL.'language.class.php');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,11 +60,6 @@
 define('DB_SYSLOG', PATH_DATABASES.'syslog.php');
 define('DB_USERS', PATH_DATABASES.'users.php');
 define('DB_SECURITY', PATH_DATABASES.'security.php');
-
-// JSON pretty print
-if (!defined('JSON_PRETTY_PRINT')) {
-	define('JSON_PRETTY_PRINT', 128);
-}
 
 // User environment variables
 include(PATH_KERNEL.'boot'.DS.'variables.php');
```
