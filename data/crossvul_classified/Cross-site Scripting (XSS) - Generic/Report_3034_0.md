# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3034_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3034_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-22 of the vulnerable file.

<?php
/*
 * LimeSurvey
 * Copyright (C) 2007-2011 The LimeSurvey Project Team / Carsten Schmitz
 * All rights reserved.
 * License: GNU/GPL License v2 or later, see LICENSE.php
 * LimeSurvey is free software. This version may have been modified pursuant
 * to the GNU General Public License, and as distributed it includes or
 * is derivative of works licensed under the GNU General Public License or
 * other free or open source software licenses.
 * See COPYRIGHT.php for copyright notices and details.
 *150413
 */

$config['versionnumber'] = '2.72.3';
$config['dbversionnumber'] = 263;
$config['buildnumber'] = '';
$config['updatable'] = true;
$config['assetsversionnumber'] = '2723';
return $config;

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,11 +12,11 @@
  *150413
  */
 
-$config['versionnumber'] = '2.72.3';
+$config['versionnumber'] = '2.72.4';
 $config['dbversionnumber'] = 263;
 $config['buildnumber'] = '';
 $config['updatable'] = true;
-$config['assetsversionnumber'] = '2723';
+$config['assetsversionnumber'] = '2724';
 return $config;
 
 ?>
```
