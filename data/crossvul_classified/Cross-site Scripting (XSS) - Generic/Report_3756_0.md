# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3756_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3756_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-33 of the vulnerable file.

<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2012 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 * @package   Zend_Debug.php
 */

namespace Zend\Debug;

/**
 * Concrete class for generating debug dumps related to the output source.
 *
 * @category   Zend
 * @package    Zend_Debug
 */
class Debug
{

    /**
     * @var string
     */
    protected static $sapi = null;

    /**
     * Get the current value of the debug output environment.
     * This defaults to the value of PHP_SAPI.
     *
     * @return string;
     */
    public static function getSapi()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,6 +10,8 @@
 
 namespace Zend\Debug;
 
+use Zend\Escaper\Escaper;
+
 /**
  * Concrete class for generating debug dumps related to the output source.
  *
@@ -18,6 +20,10 @@
  */
 class Debug
 {
+    /**
+     * @var Escaper
+     */
+    protected static $escaper = null;
 
     /**
      * @var string
@@ -51,6 +57,31 @@
     }
 
     /**
+     * Set Escaper instance
+     *
+     * @param  Escaper $escaper
+     */
+    public static function setEscaper(Escaper $escaper)
+    {
+        static::$escaper = $escaper;
+    }
+    
+    /**
+     * Get Escaper instance
+     *
+     * Lazy loads an instance if none provided.
+     *
+     * @return Escaper
+     */
+    public static function getEscaper()
+    {
+        if (null === static::$escaper) {
+            static::setEscaper(new Escaper());
+        }
+        return static::$escaper;
+    }
+
+    /**
      * Debug helper function.  This is a wrapper for var_dump() that adds
      * the <pre /> tags, cleans up newlines and indents, and runs
      * htmlentities() before output.
@@ -78,7 +109,7 @@
                     . PHP_EOL;
         } else {
             if (!extension_loaded('xdebug')) {
-                $output = htmlspecialchars($output, ENT_QUOTES);
+                $output = static::getEscaper()->escapeHtml($output);
             }
 
             $output = '<pre>'
```
