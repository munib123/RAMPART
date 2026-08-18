# CrossVul Fix Pair: Use of Insufficiently Random Values in php
**Pair ID:** 1954_1
**Vulnerability Class:** Use of Insufficiently Random Values
**CWE:** CWE-330
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1954_1`)

## Vulnerability Information & PoC

## Description
Use of Insufficiently Random Values - When product generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated, and use this guess to impersona...

## Vulnerable Code
```php
Lines 1-36 of the vulnerable file.

<?php
/* Copyright (c) Anuko International Ltd. https://www.anuko.com
License: See license.txt */

// Report all errors except E_NOTICE and E_STRICT.
// Ignoring E_STRICT is here because PEAR 1.9.4 that we use is not E_STRICT compliant.
if (!defined('E_STRICT')) define('E_STRICT', 2048);
// if (!defined('E_DEPRECATED')) define('E_DEPRECATED', 8192);
error_reporting(E_ALL & ~E_NOTICE & ~E_STRICT); // & ~E_DEPRECATED);
// E_ALL tends to change as PHP evolves, therefore we use & here instead of exclusive OR (^).

// Disable displaying errors on screen.
ini_set('display_errors', 'Off');

// require_once('init_auth.php');
define("APP_VERSION", "1.19.23.5414");
define("APP_DIR", dirname(__FILE__));
define("LIBRARY_DIR", APP_DIR."/WEB-INF/lib");
define("TEMPLATE_DIR", APP_DIR."/WEB-INF/templates");
// Date format for database and URI parameters.
define('DB_DATEFORMAT', '%Y-%m-%d');
define('MAX_RANK', 512); // Max user rank.

require_once(LIBRARY_DIR.'/common.lib.php');

// Require the configuration file with application settings.
if (!file_exists(APP_DIR."/WEB-INF/config.php")) die ("WEB-INF/config.php file does not exist.");
require_once("WEB-INF/config.php");
// Check whether DSN is defined.
if (!defined("DSN")) {
  die ("DSN value is not defined. Check your config.php file.");
}

// Depending on DSN, require either mysqli or mysql extensions.
if (strrpos(DSN, 'mysqli://', -strlen(DSN)) !== FALSE) {
  check_extension('mysqli'); // DSN starts with mysqli:// - require mysqli extension.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,7 +13,7 @@
 ini_set('display_errors', 'Off');
 
 // require_once('init_auth.php');
-define("APP_VERSION", "1.19.23.5414");
+define("APP_VERSION", "1.19.24.5415");
 define("APP_DIR", dirname(__FILE__));
 define("LIBRARY_DIR", APP_DIR."/WEB-INF/lib");
 define("TEMPLATE_DIR", APP_DIR."/WEB-INF/templates");
```
