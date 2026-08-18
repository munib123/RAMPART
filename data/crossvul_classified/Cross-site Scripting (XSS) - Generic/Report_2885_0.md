# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2885_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2885_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-14 of the vulnerable file.

<?php
/**
 * phpwcms content management system
 *
 * @author Oliver Georgi <og@phpwcms.org>
 * @copyright Copyright (c) 2002-2017, Oliver Georgi
 * @license http://opensource.org/licenses/GPL-2.0 GNU GPL-2
 * @link http://www.phpwcms.org
 *
 **/

define('PHPWCMS_VERSION', '1.8.9');
define('PHPWCMS_RELEASE_DATE', '2017/09/14');
define('PHPWCMS_REVISION', '547');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,5 +10,5 @@
  **/
 
 define('PHPWCMS_VERSION', '1.8.9');
-define('PHPWCMS_RELEASE_DATE', '2017/09/14');
+define('PHPWCMS_RELEASE_DATE', '2017/10/23');
 define('PHPWCMS_REVISION', '547');
```
