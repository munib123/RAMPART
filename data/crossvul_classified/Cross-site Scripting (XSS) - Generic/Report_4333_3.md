# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4333_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4333_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 141-181 of the vulnerable file.

     * Returns whether the escaping interceptors should be disabled or enabled for the render-result of this ViewHelper
     *
     * Note: This method is no public API, use $this->escapeChildren instead!
     *
     * @return boolean
     */
    public function isOutputEscapingEnabled()
    {
        return $this->escapeOutput !== false;
    }

    /**
     * Register a new argument. Call this method from your ViewHelper subclass
     * inside the initializeArguments() method.
     *
     * @param string $name Name of the argument
     * @param string $type Type of the argument
     * @param string $description Description of the argument
     * @param boolean $required If TRUE, argument is required. Defaults to FALSE.
     * @param mixed $defaultValue Default value of argument
     * @return \TYPO3Fluid\Fluid\Core\ViewHelper\AbstractViewHelper $this, to allow chaining.
     * @throws Exception
     * @api
     */
    protected function registerArgument($name, $type, $description, $required = false, $defaultValue = null)
    {
        if (array_key_exists($name, $this->argumentDefinitions)) {
            throw new Exception(
                'Argument "' . $name . '" has already been defined, thus it should not be defined again.',
                1253036401
            );
        }
        $this->argumentDefinitions[$name] = new ArgumentDefinition($name, $type, $description, $required, $defaultValue);
        return $this;
    }

    /**
     * Overrides a registered argument. Call this method from your ViewHelper subclass
     * inside the initializeArguments() method if you want to override a previously registered argument.
     * @see registerArgument()
     *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -158,11 +158,12 @@
      * @param string $description Description of the argument
      * @param boolean $required If TRUE, argument is required. Defaults to FALSE.
      * @param mixed $defaultValue Default value of argument
+     * @param bool|null $escape Can be toggled to TRUE to force escaping of variables and inline syntax passed as argument value.
      * @return \TYPO3Fluid\Fluid\Core\ViewHelper\AbstractViewHelper $this, to allow chaining.
      * @throws Exception
      * @api
      */
-    protected function registerArgument($name, $type, $description, $required = false, $defaultValue = null)
+    protected function registerArgument($name, $type, $description, $required = false, $defaultValue = null, $escape = null)
     {
         if (array_key_exists($name, $this->argumentDefinitions)) {
             throw new Exception(
@@ -170,7 +171,7 @@
                 1253036401
             );
         }
-        $this->argumentDefinitions[$name] = new ArgumentDefinition($name, $type, $description, $required, $defaultValue);
+        $this->argumentDefinitions[$name] = new ArgumentDefinition($name, $type, $description, $required, $defaultValue, $escape);
         return $this;
     }
 
@@ -184,11 +185,12 @@
      * @param string $description Description of the argument
      * @param boolean $required If TRUE, argument is required. Defaults to FALSE.
      * @param mixed $defaultValue Default value of argument
+     * @param bool|null $escape Can be toggled to TRUE to force escaping of variables and inline syntax passed as argument value.
      * @return \TYPO3Fluid\Fluid\Core\ViewHelper\AbstractViewHelper $this, to allow chaining.
      * @throws Exception
      * @api
      */
-    protected function overrideArgument($name, $type, $description, $required = false, $defaultValue = null)
+    protected function overrideArgument($name, $type, $description, $required = false, $defaultValue = null, $escape = null)
     {
         if (!array_key_exists($name, $this->argumentDefinitions)) {
             throw new Exception(
@@ -196,7 +198,7 @@
                 1279212461
             );
         }
-        $this->argumentDefinitions[$name] = new ArgumentDefinition($name, $type, $description, $required, $defaultValue);
+        $this->argumentDefinitions[$name] = new ArgumentDefinition($name, $type, $description, $required, $defaultValue, $escape);
         return $this;
     }
 
```
