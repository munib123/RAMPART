# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5158_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5158_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 32-75 of the vulnerable file.

    public static function getInfo()
    {
        return __(
            'Displays a link to download this image.'
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
        // must disable the page loader, see
        // https://wiki.phpmyadmin.net/pma/Page_loader#Bypassing_the_page_loader
        $transform_options = array(
            'string' => '<a class="disableAjax"'
                . ' target="_new" href="transformation_wrapper.php'
                . $options['wrapper_link'] . '" alt="[__BUFFER__]">[BLOB]</a>',
        );

        return PMA_Transformation_globalHtmlReplace(
            $buffer,
            $transform_options
        );
    }

    /* ~~~~~~~~~~~~~~~~~~~~ Getters and Setters ~~~~~~~~~~~~~~~~~~~~ */

    /**
     * Gets the transformation name of the specific plugin
     *
     * @return string
     */
    public static function getName()
    {
        return "ImageLink";
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,16 +49,8 @@
     {
         // must disable the page loader, see
         // https://wiki.phpmyadmin.net/pma/Page_loader#Bypassing_the_page_loader
-        $transform_options = array(
-            'string' => '<a class="disableAjax"'
-                . ' target="_new" href="transformation_wrapper.php'
-                . $options['wrapper_link'] . '" alt="[__BUFFER__]">[BLOB]</a>',
-        );
-
-        return PMA_Transformation_globalHtmlReplace(
-            $buffer,
-            $transform_options
-        );
+        return '<a class="disableAjax" target="_new" href="transformation_wrapper.php'
+            . $options['wrapper_link'] . '" alt="[' . htmlspecialchars($buffer) . ']">[BLOB]</a>';
     }
 
     /* ~~~~~~~~~~~~~~~~~~~~ Getters and Setters ~~~~~~~~~~~~~~~~~~~~ */
```
