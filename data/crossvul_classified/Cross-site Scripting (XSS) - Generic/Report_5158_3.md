# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5158_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5158_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 32-80 of the vulnerable file.

    public static function getInfo()
    {
        return __(
            'Displays a clickable thumbnail. The options are the maximum width'
            . ' and height in pixels. The original aspect ratio is preserved.'
        );
    }

    /**
     * Does the actual work of each specific transformations plugin.
     *
     * @param string $buffer  text to be transformed
     * @param array  $options transformation options
     * @param string $meta    meta information
     *
     * @return string
     */
    public function applyTransformation($buffer, $options = array(), $meta = '')
    {
        if (PMA_IS_GD2) {
            $transform_options = array(
                'string' => '<a href="transformation_wrapper.php'
                    . $options['wrapper_link']
                    . '" target="_blank"><img src="transformation_wrapper.php'
                    . $options['wrapper_link'] . '&amp;resize=jpeg&amp;newWidth='
                    . (isset($options[0]) ? $options[0] : '100') . '&amp;newHeight='
                    . (isset($options[1]) ? $options[1] : 100)
                    . '" alt="[__BUFFER__]" border="0" /></a>',
            );
        } else {
            $transform_options = array(
                'string' => '<img src="transformation_wrapper.php'
                    . $options['wrapper_link']
                    . '" alt="[__BUFFER__]" width="320" height="240" />',
            );
        }

        return PMA_Transformation_globalHtmlReplace(
            $buffer,
            $transform_options
        );
    }


    /* ~~~~~~~~~~~~~~~~~~~~ Getters and Setters ~~~~~~~~~~~~~~~~~~~~ */

    /**
     * Gets the transformation name of the specific plugin
     *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,28 +49,20 @@
     public function applyTransformation($buffer, $options = array(), $meta = '')
     {
         if (PMA_IS_GD2) {
-            $transform_options = array(
-                'string' => '<a href="transformation_wrapper.php'
-                    . $options['wrapper_link']
-                    . '" target="_blank"><img src="transformation_wrapper.php'
-                    . $options['wrapper_link'] . '&amp;resize=jpeg&amp;newWidth='
-                    . (isset($options[0]) ? $options[0] : '100') . '&amp;newHeight='
-                    . (isset($options[1]) ? $options[1] : 100)
-                    . '" alt="[__BUFFER__]" border="0" /></a>',
-            );
+            return '<a href="transformation_wrapper.php'
+                . $options['wrapper_link']
+                . '" target="_blank"><img src="transformation_wrapper.php'
+                . $options['wrapper_link'] . '&amp;resize=jpeg&amp;newWidth='
+                . (isset($options[0]) ? $options[0] : '100') . '&amp;newHeight='
+                . (isset($options[1]) ? $options[1] : 100)
+                . '" alt="[' . htmlspecialchars($buffer) . ']" border="0" /></a>';
         } else {
-            $transform_options = array(
-                'string' => '<img src="transformation_wrapper.php'
-                    . $options['wrapper_link']
-                    . '" alt="[__BUFFER__]" width="320" height="240" />',
-            );
+            return '<img src="transformation_wrapper.php'
+                . $options['wrapper_link']
+                . '" alt="[' . htmlspecialchars($buffer) . ']" width="320" height="240" />';
         }
+    }
 
-        return PMA_Transformation_globalHtmlReplace(
-            $buffer,
-            $transform_options
-        );
-    }
 
 
     /* ~~~~~~~~~~~~~~~~~~~~ Getters and Setters ~~~~~~~~~~~~~~~~~~~~ */
```
