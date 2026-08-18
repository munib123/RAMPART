# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4333_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4333_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-35 of the vulnerable file.

<?php
namespace TYPO3Fluid\Fluid\Core\Parser;

/*
 * This file belongs to the package "TYPO3 Fluid".
 * See LICENSE.txt that was shipped with this package.
 */

/**
 * The parser configuration. Contains all configuration needed to configure
 * the building of a SyntaxTree.
 */
class Configuration
{

    /**
     * Generic interceptors registered with the configuration.
     *
     * @var \SplObjectStorage[]
     */
    protected $interceptors = [];

    /**
     * Escaping interceptors registered with the configuration.
     *
     * @var \SplObjectStorage[]
     */
    protected $escapingInterceptors = [];

    /**
     * Adds an interceptor to apply to values coming from object accessors.
     *
     * @param InterceptorInterface $interceptor
     * @return void
     */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,6 +12,10 @@
  */
 class Configuration
 {
+    /**
+     * @var bool
+     */
+    protected $viewHelperArgumentEscapingEnabled = true;
 
     /**
      * Generic interceptors registered with the configuration.
@@ -26,6 +30,22 @@
      * @var \SplObjectStorage[]
      */
     protected $escapingInterceptors = [];
+
+    /**
+     * @return bool
+     */
+    public function isViewHelperArgumentEscapingEnabled()
+    {
+        return $this->viewHelperArgumentEscapingEnabled;
+    }
+
+    /**
+     * @param bool $viewHelperArgumentEscapingEnabled
+     */
+    public function setViewHelperArgumentEscapingEnabled($viewHelperArgumentEscapingEnabled): void
+    {
+        $this->viewHelperArgumentEscapingEnabled = (bool) $viewHelperArgumentEscapingEnabled;
+    }
 
     /**
      * Adds an interceptor to apply to values coming from object accessors.
```
