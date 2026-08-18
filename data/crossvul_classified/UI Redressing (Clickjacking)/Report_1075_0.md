# CrossVul Fix Pair: Improper Restriction of Rendered UI Layers or Frames in php
**Pair ID:** 1075_0
**Vulnerability Class:** UI Redressing (Clickjacking)
**CWE:** CWE-1021
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1075_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Rendered UI Layers or Frames - A web application is expected to place restrictions on whether it is allowed to be rendered within frames, iframes, objects, embed or applet elements.

## Vulnerable Code
```php
Lines 1-20 of the vulnerable file.

<?php
/*
 * LimeSurvey
 * Copyright (C) 2007-2016 The LimeSurvey Project Team / Carsten Schmitz
 * All rights reserved.
 * License: GNU/GPL License v3 or later, see LICENSE.php
 * LimeSurvey is free software. This version may have been modified pursuant
 * to the GNU General Public License, and as distributed it includes or
 * is derivative of works licensed under the GNU General Public License or
 * other free or open source software licenses.
 * See COPYRIGHT.php for copyright notices and details.
 */


$config['versionnumber'] = '3.17.13';
$config['dbversionnumber'] = 359;
$config['buildnumber'] = '';
$config['updatable'] = true;
$config['assetsversionnumber'] = '30095';
return $config;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,9 +12,9 @@
  */
 
 
-$config['versionnumber'] = '3.17.13';
+$config['versionnumber'] = '3.17.14';
 $config['dbversionnumber'] = 359;
 $config['buildnumber'] = '';
 $config['updatable'] = true;
-$config['assetsversionnumber'] = '30095';
+$config['assetsversionnumber'] = '30096';
 return $config;
```
