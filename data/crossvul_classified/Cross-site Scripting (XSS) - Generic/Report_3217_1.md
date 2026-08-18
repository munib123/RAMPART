# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3217_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3217_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 482-522 of the vulnerable file.

        if (preg_match('/\.([a-z0-9]+)$/', $filename, $m)) {
            if (!in_array($m[1], $classes)) {
                $classes[] = $m[1];
            }
        }

        return join(" ", $classes);
    }

    /**
     * Decode escaped entities used by known XSS exploits.
     * See http://downloads.securityfocus.com/vulnerabilities/exploits/26800.eml for examples
     *
     * @param string CSS content to decode
     *
     * @return string Decoded string
     */
    public static function xss_entity_decode($content)
    {
        $out = html_entity_decode(html_entity_decode($content));
        $out = preg_replace_callback('/\\\([0-9a-f]{4})/i',
            array(self, 'xss_entity_decode_callback'), $out);
        $out = preg_replace('#/\*.*\*/#Ums', '', $out);

        return $out;
    }

    /**
     * preg_replace_callback callback for xss_entity_decode
     *
     * @param array $matches Result from preg_replace_callback
     *
     * @return string Decoded entity
     */
    public static function xss_entity_decode_callback($matches)
    {
        return chr(hexdec($matches[1]));
    }

    /**
     * Check if we can process not exceeding memory_limit
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -499,6 +499,7 @@
     public static function xss_entity_decode($content)
     {
         $out = html_entity_decode(html_entity_decode($content));
+        $out = strip_tags($out);
         $out = preg_replace_callback('/\\\([0-9a-f]{4})/i',
             array(self, 'xss_entity_decode_callback'), $out);
         $out = preg_replace('#/\*.*\*/#Ums', '', $out);
```
