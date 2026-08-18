# CrossVul Fix Pair: 7PK in php
**Pair ID:** 5132_0
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5132_0`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```php
Lines 1376-1420 of the vulnerable file.

        }

        $this->set('is_https', $is_https);

        return $is_https;
    }

    /**
     * Get cookie path
     *
     * @return string
     */
    public function getCookiePath()
    {
        static $cookie_path = null;

        if (null !== $cookie_path && !defined('TESTSUITE')) {
            return $cookie_path;
        }

        if (isset($GLOBALS['PMA_PHP_SELF'])) {
            $parsed_url = parse_url($GLOBALS['PMA_PHP_SELF']);
        } else {
            $parsed_url = parse_url(PMA_getenv('REQUEST_URI'));
        }

        $parts = explode(
            '/',
            rtrim(str_replace('\\', '/', $parsed_url['path']), '/')
        );

        /* Remove filename */
        if (substr($parts[count($parts) - 1], -4) == '.php') {
            $parts = array_slice($parts, 0, count($parts) - 1);
        }

        /* Remove extra path from javascript calls */
        if (defined('PMA_PATH_TO_BASEDIR')) {
            $parts = array_slice($parts, 0, count($parts) - 1);
        }

        $parts[] = '';

        return implode('/', $parts);
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1393,11 +1393,7 @@
             return $cookie_path;
         }
 
-        if (isset($GLOBALS['PMA_PHP_SELF'])) {
-            $parsed_url = parse_url($GLOBALS['PMA_PHP_SELF']);
-        } else {
-            $parsed_url = parse_url(PMA_getenv('REQUEST_URI'));
-        }
+        $parsed_url = parse_url($GLOBALS['PMA_PHP_SELF']);
 
         $parts = explode(
             '/',
```
