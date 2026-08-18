# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5158_7
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5158_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-38 of the vulnerable file.

<?php
/* vim: set expandtab sw=4 ts=4 sts=4: */
/**
 * Abstract class for the image link transformations plugins
 *
 * @package    PhpMyAdmin-Transformations
 * @subpackage ImageLink
 */
namespace PMA\libraries\plugins\transformations\abs;

use PMA\libraries\plugins\TransformationsPlugin;

if (!defined('PHPMYADMIN')) {
    exit;
}

/* For PMA_Transformation_globalHtmlReplace */
require_once 'libraries/transformations.lib.php';

/**
 * Provides common methods for all of the image link transformations plugins.
 *
 * @package PhpMyAdmin
 */
abstract class TextImageLinkTransformationsPlugin extends TransformationsPlugin
{
    /**
     * Gets the transformation description of the specific plugin
     *
     * @return string
     */
    public static function getInfo()
    {
        return __(
            'Displays an image and a link; the column contains the filename. The'
            . ' first option is a URL prefix like "http://www.example.com/". The'
            . ' second and third options are the width and the height in pixels.'
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
  * Provides common methods for all of the image link transformations plugins.
@@ -49,21 +46,12 @@
      */
     public function applyTransformation($buffer, $options = array(), $meta = '')
     {
-        $transform_options = array(
-            'string' => '<a href="' . (isset($options[0]) ? $options[0] : '')
-                . $buffer . '" target="_blank"><img src="'
-                . (isset($options[0]) ? $options[0] : '') . $buffer
-                . '" border="0" width="' . (isset($options[1]) ? $options[1] : 100)
-                . '" height="' . (isset($options[2]) ? $options[2] : 50) . '" />'
-                . $buffer . '</a>',
-        );
-
-        $buffer = PMA_Transformation_globalHtmlReplace(
-            $buffer,
-            $transform_options
-        );
-
-        return $buffer;
+        return '<a href="' . htmlspecialchars(isset($options[0]) ? $options[0] : '')
+            . htmlspecialchars($buffer) . '" target="_blank"><img src="'
+            . htmlspecialchars(isset($options[0]) ? $options[0] : '') . htmlspecialchars($buffer)
+            . '" border="0" width="' . (isset($options[1]) ? $options[1] : 100)
+            . '" height="' . (isset($options[2]) ? $options[2] : 50) . '" />'
+            . htmlspecialchars($buffer) . '</a>';
     }
 
 
```
