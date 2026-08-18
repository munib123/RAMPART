# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5158_8
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5158_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-38 of the vulnerable file.

<?php
/* vim: set expandtab sw=4 ts=4 sts=4: */
/**
 * Abstract class for the link transformations plugins
 *
 * @package    PhpMyAdmin-Transformations
 * @subpackage Link
 */
namespace PMA\libraries\plugins\transformations\abs;

use PMA\libraries\plugins\TransformationsPlugin;

if (!defined('PHPMYADMIN')) {
    exit;
}

/* For PMA_Transformation_globalHtmlReplace */
require_once 'libraries/transformations.lib.php';

/**
 * Provides common methods for all of the link transformations plugins.
 *
 * @package PhpMyAdmin
 */
abstract class TextLinkTransformationsPlugin extends TransformationsPlugin
{
    /**
     * Gets the transformation description of the specific plugin
     *
     * @return string
     */
    public static function getInfo()
    {
        return __(
            'Displays a link; the column contains the filename. The first option'
            . ' is a URL prefix like "http://www.example.com/". The second option'
            . ' is a title for the link.'
        );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,9 +13,6 @@
 if (!defined('PHPMYADMIN')) {
     exit;
 }
-
-/* For PMA_Transformation_globalHtmlReplace */
-require_once 'libraries/transformations.lib.php';
 
 /**
  * Provides common methods for all of the link transformations plugins.
@@ -49,24 +46,18 @@
      */
     public function applyTransformation($buffer, $options = array(), $meta = '')
     {
-
         $append_part = (isset($options[2]) && $options[2]) ? '' : $buffer;
 
-        $transform_options = array(
-            'string' => '<a href="'
-                . (isset($options[0]) ? $options[0] : '') . $append_part
-                . '" title="'
-                . htmlspecialchars(isset($options[1]) ? $options[1] : '')
-                . '" target="_new">'
-                . htmlspecialchars(isset($options[1]) ? $options[1] : $buffer)
-                . '</a>',
-        );
+        return '<a href="'
+            . htmlspecialchars(isset($options[0]) ? $options[0] : '')
+            . htmlspecialchars($append_part)
+            . '" title="'
+            . htmlspecialchars(isset($options[1]) ? $options[1] : '')
+            . '" target="_new">'
+            . htmlspecialchars(isset($options[1]) ? $options[1] : $buffer)
+            . '</a>';
+    }
 
-        return PMA_Transformation_globalHtmlReplace(
-            $buffer,
-            $transform_options
-        );
-    }
 
     /* ~~~~~~~~~~~~~~~~~~~~ Getters and Setters ~~~~~~~~~~~~~~~~~~~~ */
 
```
