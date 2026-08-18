# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in php
**Pair ID:** 4191_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4191_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```php
Lines 20-60 of the vulnerable file.

// |
// | This license applies to this document only, not any other software
// | that it may be combined with.
// |
// +----------------------------------------------------------------------+
// | Contributors:
// | https://www.anuko.com/time_tracker/credits.htm
// +----------------------------------------------------------------------+

// Report all errors except E_NOTICE and E_STRICT.
// Ignoring E_STRICT is here because PEAR 1.9.4 that we use is not E_STRICT compliant.
if (!defined('E_STRICT')) define('E_STRICT', 2048);
// if (!defined('E_DEPRECATED')) define('E_DEPRECATED', 8192);
error_reporting(E_ALL & ~E_NOTICE & ~E_STRICT); // & ~E_DEPRECATED);
// E_ALL tends to change as PHP evloves, therefore we use & here instead of exclusive OR (^).

// Disable displaying errors on screen.
ini_set('display_errors', 'Off');

// require_once('init_auth.php');
define("APP_VERSION", "1.19.23.5324");
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
@@ -37,7 +37,7 @@
 ini_set('display_errors', 'Off');
 
 // require_once('init_auth.php');
-define("APP_VERSION", "1.19.23.5324");
+define("APP_VERSION", "1.19.23.5325");
 define("APP_DIR", dirname(__FILE__));
 define("LIBRARY_DIR", APP_DIR."/WEB-INF/lib");
 define("TEMPLATE_DIR", APP_DIR."/WEB-INF/templates");
```
