# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3756_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3756_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-37 of the vulnerable file.

<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2012 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 * @package   Zend_Log
 */

namespace Zend\Log\Formatter;

use DateTime;
use DOMDocument;
use DOMElement;
use Traversable;
use Zend\Stdlib\ArrayUtils;

/**
 * @category   Zend
 * @package    Zend_Log
 * @subpackage Formatter
 */
class Xml implements FormatterInterface
{
    /**
     * @var string Name of root element
     */
    protected $rootElement;

    /**
     * @var array Relates XML elements to log data field keys.
     */
    protected $elementMap;

    /**
     * @var string Encoding to use in XML
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,6 +14,7 @@
 use DOMDocument;
 use DOMElement;
 use Traversable;
+use Zend\Escaper\Escaper;
 use Zend\Stdlib\ArrayUtils;
 
 /**
@@ -39,6 +40,11 @@
     protected $encoding;
 
     /**
+     * @var Escaper instance
+     */
+    protected $escaper;
+
+    /**
      * Format specifier for DateTime objects in event data (default: ISO 8601)
      *
      * @see http://php.net/manual/en/function.date.php
@@ -119,6 +125,33 @@
     {
         $this->encoding = (string) $value;
         return $this;
+    }
+
+    /**
+     * Set Escaper instance
+     *
+     * @param  Escaper $escaper
+     * @return Xml
+     */
+    public function setEscaper(Escaper $escaper)
+    {
+        $this->escaper = $escaper;
+        return $this;
+    }
+    
+    /**
+     * Get Escaper instance
+     *
+     * Lazy-loads an instance with the current encoding if none registered.
+     *
+     * @return Escaper
+     */
+    public function getEscaper()
+    {
+        if (null === $this->escaper) {
+            $this->setEscaper(new Escaper($this->getEncoding()));
+        }
+        return $this->escaper;
     }
 
     /**
@@ -142,9 +175,10 @@
             }
         }
 
-        $enc = $this->getEncoding();
-        $dom = new DOMDocument('1.0', $enc);
-        $elt = $dom->appendChild(new DOMElement($this->rootElement));
+        $enc     = $this->getEncoding();
+        $escaper = $this->getEscaper();
+        $dom     = new DOMDocument('1.0', $enc);
+        $elt     = $dom->appendChild(new DOMElement($this->rootElement));
 
         foreach ($dataToInsert as $key => $value) {
             if (empty($value)
@@ -152,7 +186,7 @@
                 || (is_object($value) && method_exists($value,'__toString'))
             ) {
                 if ($key == "message") {
-                    $value = htmlspecialchars($value, ENT_COMPAT, $enc);
+                    $value = $escaper->escapeHtml($value);
                 } elseif ($key == "extra" && empty($value)) {
                     continue;
                 }
```
