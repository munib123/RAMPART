# CrossVul Fix Pair: Incorrect Default Permissions in php
**Pair ID:** 3883_0
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-276
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3883_0`)

## Vulnerability Information & PoC

## Description
Incorrect Default Permissions - During installation, installed file permissions are set to allow anyone to modify those files.

## Vulnerable Code
```php
Lines 30-65 of the vulnerable file.

     * Detects the environment when called via Console
     * @return string
     */
    protected static function _detectCli() {
        $environment = self::DEVELOPMENT;
        $uname = php_uname('n');
        if (strpos($uname, 'master') !== false) {
            $environment = self::PRODUCTION;
        } else if (strpos($uname, 'stage') !== false) {
            $environment = self::STAGING;
        }

        return $environment;
    }

    /**
     * Detects the environment when called via HTTP
     * @return string
     */
    protected static function _detectHttp() {
        $host = env('HTTP_HOST');

        if (substr($host, 0, 4) == 'dev.') {
            $environment = self::DEVELOPMENT;
        } else if (substr($host, 0, 4) == 'dev-') {
            $environment = self::DEVELOPMENT;
        } else if (substr($host, 0, 8) == 'staging.') {
            $environment = self::STAGING;
        } else {
            $environment = self::PRODUCTION;
        }

        return $environment;

    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,19 +47,18 @@
      * @return string
      */
     protected static function _detectHttp() {
-        $host = env('HTTP_HOST');
+        $environment = self::PRODUCTION;
 
-        if (substr($host, 0, 4) == 'dev.') {
-            $environment = self::DEVELOPMENT;
-        } else if (substr($host, 0, 4) == 'dev-') {
-            $environment = self::DEVELOPMENT;
-        } else if (substr($host, 0, 8) == 'staging.') {
-            $environment = self::STAGING;
-        } else {
-            $environment = self::PRODUCTION;
+        // To enable debug mode please add
+        // fastcgi_param OITC_DEBUG 1;
+        // to your nginx config
+
+        if (isset($_SERVER['OITC_DEBUG'])) {
+            if ($_SERVER['OITC_DEBUG'] === '1') {
+                $environment = self::DEVELOPMENT;
+            }
         }
-
+        
         return $environment;
-
     }
 }
```
