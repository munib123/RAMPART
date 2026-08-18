# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 644_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `644_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 184-203 of the vulnerable file.

            return round($bytes / 1073741824 * 1024).' MB';
        } else {
            return round($bytes / 1073741824, 3).' GB';
        }
    }
}

if (!function_exists('iso8601')) {
    /**
     * Converts timestamp to ISO8601 format.
     *
     * @param string $time
     *
     * @return string
     */
    function iso8601($time)
    {
        return gmdate('c', strtotime($time));
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -201,3 +201,20 @@
         return gmdate('c', strtotime($time));
     }
 }
+
+if (!function_exists('strToHex')) {
+    /**
+     * Converts timestamp to ISO8601 format.
+     *
+     * @param string $string
+     *
+     * @return string
+     */
+    function strToHex($string) {
+        $hex = bin2hex($string);
+        $hex = chunk_split($hex, 2, "\\x");
+        $hex = "\\x" . substr($hex, 0, -2);
+
+        return $hex;
+    }
+}
```
