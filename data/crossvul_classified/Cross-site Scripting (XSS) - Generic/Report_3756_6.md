# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3756_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3756_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-36 of the vulnerable file.

<?php
/**
 * Zend Framework (http://framework.zend.com/)
 *
 * @link      http://github.com/zendframework/zf2 for the canonical source repository
 * @copyright Copyright (c) 2005-2012 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 * @package   Zend_Tag
 */

namespace Zend\Tag\Cloud\Decorator;

use Traversable;
use Zend\Stdlib\ArrayUtils;
use Zend\Tag\Cloud\Decorator\DecoratorInterface as Decorator;

/**
 * Abstract class for cloud decorators
 *
 * @category  Zend
 * @package   Zend_Tag
 */
abstract class AbstractCloud implements Decorator
{
    /**
     * Option keys to skip when calling setOptions()
     *
     * @var array
     */
    protected $skipOptions = array(
        'options',
        'config',
    );

    /**
     * Create a new cloud decorator with options
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,62 +10,12 @@
 
 namespace Zend\Tag\Cloud\Decorator;
 
-use Traversable;
-use Zend\Stdlib\ArrayUtils;
-use Zend\Tag\Cloud\Decorator\DecoratorInterface as Decorator;
-
 /**
  * Abstract class for cloud decorators
  *
  * @category  Zend
  * @package   Zend_Tag
  */
-abstract class AbstractCloud implements Decorator
+abstract class AbstractCloud extends AbstractDecorator
 {
-    /**
-     * Option keys to skip when calling setOptions()
-     *
-     * @var array
-     */
-    protected $skipOptions = array(
-        'options',
-        'config',
-    );
-
-    /**
-     * Create a new cloud decorator with options
-     *
-     * @param  array|Traversable $options
-     */
-    public function __construct($options = null)
-    {
-        if ($options instanceof Traversable) {
-            $options = ArrayUtils::iteratorToArray($options);
-        }
-        if (is_array($options)) {
-            $this->setOptions($options);
-        }
-    }
-
-    /**
-     * Set options from array
-     *
-     * @param  array $options Configuration for the decorator
-     * @return AbstractCloud
-     */
-    public function setOptions(array $options)
-    {
-        foreach ($options as $key => $value) {
-            if (in_array(strtolower($key), $this->skipOptions)) {
-                continue;
-            }
-
-            $method = 'set' . $key;
-            if (method_exists($this, $method)) {
-                $this->$method($value);
-            }
-        }
-
-        return $this;
-    }
 }
```
