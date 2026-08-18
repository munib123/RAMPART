# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3756_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3756_2`)

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
 * @package   Zend_Feed
 */

namespace Zend\Feed\PubSubHubbub;

use Zend\Feed\Reader;
use Zend\Http;

/**
 * @category   Zend
 * @package    Zend_Feed_Pubsubhubbub
 */
class PubSubHubbub
{
    /**
     * Verification Modes
     */
    const VERIFICATION_MODE_SYNC  = 'sync';
    const VERIFICATION_MODE_ASYNC = 'async';

    /**
     * Subscription States
     */
    const SUBSCRIPTION_VERIFIED    = 'verified';
    const SUBSCRIPTION_NOTVERIFIED = 'not_verified';
    const SUBSCRIPTION_TODELETE    = 'to_delete';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,6 +10,7 @@
 
 namespace Zend\Feed\PubSubHubbub;
 
+use Zend\Escaper\Escaper;
 use Zend\Feed\Reader;
 use Zend\Http;
 
@@ -33,9 +34,14 @@
     const SUBSCRIPTION_TODELETE    = 'to_delete';
 
     /**
+     * @var Escaper
+     */
+    protected static $escaper;
+
+    /**
      * Singleton instance if required of the HTTP client
      *
-     * @var \Zend\Http\Client
+     * @var Http\Client
      */
     protected static $httpClient = null;
 
@@ -67,7 +73,7 @@
      * Allows the external environment to make Zend_Oauth use a specific
      * Client instance.
      *
-     * @param  \Zend\Http\Client $httpClient
+     * @param  Http\Client $httpClient
      * @return void
      */
     public static function setHttpClient(Http\Client $httpClient)
@@ -80,15 +86,15 @@
      * the instance is reset and cleared of previous parameters GET/POST.
      * Headers are NOT reset but handled by this component if applicable.
      *
-     * @return \Zend\Http\Client
+     * @return Http\Client
      */
     public static function getHttpClient()
     {
-        if (!isset(self::$httpClient)):
+        if (!isset(self::$httpClient)) {
             self::$httpClient = new Http\Client;
-        else:
+        } else {
             self::$httpClient->resetParameters();
-        endif;
+        }
         return self::$httpClient;
     }
 
@@ -104,6 +110,33 @@
     }
 
     /**
+     * Set the Escaper instance
+     *
+     * If null, resets the instance
+     * 
+     * @param  null|Escaper $escaper 
+     */
+    public static function setEscaper(Escaper $escaper = null)
+    {
+        static::$escaper = $escaper;
+    }
+
+    /**
+     * Get the Escaper instance
+     *
+     * If none registered, lazy-loads an instance.
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
      * RFC 3986 safe url encoding method
      *
      * @param  string $string
@@ -111,7 +144,8 @@
      */
     public static function urlencode($string)
     {
-        $rawencoded = rawurlencode($string);
+        $escaper    = static::getEscaper();
+        $rawencoded = $escaper->escapeUrl($string);
         $rfcencoded = str_replace('%7E', '~', $rawencoded);
         return $rfcencoded;
     }
```
