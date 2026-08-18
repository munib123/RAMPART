# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 703_9
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `703_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-22 of the vulnerable file.

<?php
/* set latest version */
define("VERSION", "1.4");									//decimal release version e.g 1.32
/* set latest version */
define("VERSION_VISIBLE", "1.4");							//visible version in footer e.g 1.3.2
/* set latest revision */
define("REVISION", "030");									//increment on static content changes (js/css) or point releases to avoid caching issues
/* set last possible upgrade */
define("LAST_POSSIBLE", "1.1");								//minimum required version to be able to upgrade

// Automatically set DBVERSION as everyone forgets!
function get_dbversion() {
    require('upgrade_queries.php');
    $upgrade_keys = array_keys($upgrade_queries);
    return str_replace(VERSION.".", "", end($upgrade_keys));
}

if(!defined('DBVERSION'))
define('DBVERSION', get_dbversion());

/* prefix for css/js */
define("SCRIPT_PREFIX", VERSION_VISIBLE.'_r'.REVISION.'_v'.DBVERSION);		//css and js folder prefix to prevent caching issues
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,7 @@
 /* set latest version */
 define("VERSION_VISIBLE", "1.4");							//visible version in footer e.g 1.3.2
 /* set latest revision */
-define("REVISION", "030");									//increment on static content changes (js/css) or point releases to avoid caching issues
+define("REVISION", "031");									//increment on static content changes (js/css) or point releases to avoid caching issues
 /* set last possible upgrade */
 define("LAST_POSSIBLE", "1.1");								//minimum required version to be able to upgrade
 
```
