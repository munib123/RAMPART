# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4315_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4315_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 599-639 of the vulnerable file.

        $in = array(
        );

        // And replace them by...
        $out = array(
        );

        $in[] = '[/*]';
        $in[] = '[*]';
        $out[] = '</li>';
        $out[] = '<li>';

        $text = str_replace($in, $out, $text);

        // BBCode to find...
        $in = array( 	 '/\[b\](.*?)\[\/b\]/ms',
            '/\[i\](.*?)\[\/i\]/ms',
            '/\[u\](.*?)\[\/u\]/ms',
            '/\[mark\](.*?)\[\/mark\]/ms',
            '/\[s\](.*?)\[\/s\]/ms',
            '/\[list\=(.*?)\](.*?)\[\/list\]/ms',
            '/\[list\](.*?)\[\/list\]/ms',
            '/\[\*\]\s?(.*?)\n/ms',
            '/\[fs(.*?)\](.*?)\[\/fs(.*?)\]/ms',
            '/\[color\=(.*?)\](.*?)\[\/color\]/ms'
        );

        // And replace them by...
        $out = array(	 '\1',
            '\1',
            '\1',
            '\1',
            '\1',
            '\2',
            '\1',
            '\1',
            '\2',
            '\2'
        );

        $text = preg_replace($in, $out, $text);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -616,11 +616,11 @@
             '/\[u\](.*?)\[\/u\]/ms',
             '/\[mark\](.*?)\[\/mark\]/ms',
             '/\[s\](.*?)\[\/s\]/ms',
-            '/\[list\=(.*?)\](.*?)\[\/list\]/ms',
+            '/\[list\=([0-9]+)\](.*?)\[\/list\]/ms',
             '/\[list\](.*?)\[\/list\]/ms',
             '/\[\*\]\s?(.*?)\n/ms',
-            '/\[fs(.*?)\](.*?)\[\/fs(.*?)\]/ms',
-            '/\[color\=(.*?)\](.*?)\[\/color\]/ms'
+            '/\[fs([0-9]+)\](.*?)\[\/fs\]/ms',
+            '/\[color\=([A-Za-z0-9]{2,6})\](.*?)\[\/color\]/ms'
         );
 
         // And replace them by...
```
