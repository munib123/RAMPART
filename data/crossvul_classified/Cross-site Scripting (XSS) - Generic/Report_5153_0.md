# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5153_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5153_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 29-69 of the vulnerable file.

    public static function getInfo()
    {
        return __(
            'Displays an image and a link; the column contains the filename. The'
            . ' first option is a URL prefix like "http://www.example.com/". The'
            . ' second and third options are the width and the height in pixels.'
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
        return '<a href="' . htmlspecialchars(isset($options[0]) ? $options[0] : '')
            . htmlspecialchars($buffer) . '" target="_blank"><img src="'
            . htmlspecialchars(isset($options[0]) ? $options[0] : '') . htmlspecialchars($buffer)
            . '" border="0" width="' . (isset($options[1]) ? $options[1] : 100)
            . '" height="' . (isset($options[2]) ? $options[2] : 50) . '" />'
            . htmlspecialchars($buffer) . '</a>';
    }


    /* ~~~~~~~~~~~~~~~~~~~~ Getters and Setters ~~~~~~~~~~~~~~~~~~~~ */

    /**
     * Gets the transformation name of the specific plugin
     *
     * @return string
     */
    public static function getName()
    {
        return "Image Link";
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,9 +46,14 @@
      */
     public function applyTransformation($buffer, $options = array(), $meta = '')
     {
-        return '<a href="' . htmlspecialchars(isset($options[0]) ? $options[0] : '')
-            . htmlspecialchars($buffer) . '" target="_blank"><img src="'
-            . htmlspecialchars(isset($options[0]) ? $options[0] : '') . htmlspecialchars($buffer)
+        $url = (isset($options[0]) ? $options[0] : '') . $buffer;
+        $parsed = parse_url($url);
+        /* Do not allow javascript links */
+        if (isset($parsed['scheme']) && $parsed['scheme'] == 'javascript') {
+            return htmlspecialchars($url);
+        }
+        return '<a href="' . htmlspecialchars($url)
+            . '" target="_blank"><img src="' . htmlspecialchars($url)
             . '" border="0" width="' . (isset($options[1]) ? $options[1] : 100)
             . '" height="' . (isset($options[2]) ? $options[2] : 50) . '" />'
             . htmlspecialchars($buffer) . '</a>';
```
