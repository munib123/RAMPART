# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5158_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5158_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-33 of the vulnerable file.

<?php
/* vim: set expandtab sw=4 ts=4 sts=4: */
/**
 * Abstract class for the date format transformations plugins
 *
 * @package    PhpMyAdmin-Transformations
 * @subpackage DateFormat
 */
namespace PMA\libraries\plugins\transformations\abs;

use PMA;
use PMA\libraries\plugins\TransformationsPlugin;

/**
 * Provides common methods for all of the date format transformations plugins.
 *
 * @package PhpMyAdmin
 */
abstract class DateFormatTransformationsPlugin extends TransformationsPlugin
{
    /**
     * Gets the transformation description of the specific plugin
     *
     * @return string
     */
    public static function getInfo()
    {
        return __(
            'Displays a TIME, TIMESTAMP, DATETIME or numeric unix timestamp'
            . ' column as formatted date. The first option is the offset (in'
            . ' hours) which will be added to the timestamp (Default: 0). Use'
            . ' second option to specify a different date/time format string.'
            . ' Third option determines whether you want to see local date or'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,6 +10,8 @@
 
 use PMA;
 use PMA\libraries\plugins\TransformationsPlugin;
+
+require_once 'libraries/js_escape.lib.php';
 
 /**
  * Provides common methods for all of the date format transformations plugins.
@@ -145,11 +147,11 @@
             } else {
                 $text = 'INVALID DATE TYPE';
             }
-            $buffer = '<dfn onclick="alert(\'' . $source . '\');" title="'
-                . $source . '">' . $text . '</dfn>';
+            return '<dfn onclick="alert(\'' . PMA_jsFormat($source, false) . '\');" title="'
+                . htmlspecialchars($source) . '">' . htmlspecialchars($text) . '</dfn>';
+        } else {
+            return htmlspecialchars($buffer);
         }
-
-        return $buffer;
     }
 
     /* ~~~~~~~~~~~~~~~~~~~~ Getters and Setters ~~~~~~~~~~~~~~~~~~~~ */
```
