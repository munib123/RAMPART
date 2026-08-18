# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4333_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4333_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 31-71 of the vulnerable file.

     *
     * @var string
     */
    protected $description;

    /**
     * Is argument required?
     *
     * @var boolean
     */
    protected $required = false;

    /**
     * Default value for argument
     *
     * @var mixed
     */
    protected $defaultValue = null;

    /**
     * Constructor for this argument definition.
     *
     * @param string $name Name of argument
     * @param string $type Type of argument
     * @param string $description Description of argument
     * @param boolean $required TRUE if argument is required
     * @param mixed $defaultValue Default value
     */
    public function __construct($name, $type, $description, $required, $defaultValue = null)
    {
        $this->name = $name;
        $this->type = $type;
        $this->description = $description;
        $this->required = $required;
        $this->defaultValue = $defaultValue;
    }

    /**
     * Get the name of the argument
     *
     * @return string Name of argument
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,6 +48,21 @@
     protected $defaultValue = null;
 
     /**
+     * Escaping instruction, in line with $this->escapeOutput / $this->escapeChildren on ViewHelpers.
+     *
+     * A value of NULL means "use default behavior" (which is to escape nodes contained in the value).
+     *
+     * A value of TRUE means "escape unless escaping is disabled" (e.g. if argument is used in a ViewHelper nested
+     * within f:format.raw which disables escaping, the argument will not be escaped).
+     *
+     * A value of FALSE means "never escape argument" (as in behavior of f:format.raw, which supports both passing
+     * argument as actual argument or as tag content, but wants neither to be escaped).
+     *
+     * @var bool|null
+     */
+    protected $escape = null;
+
+    /**
      * Constructor for this argument definition.
      *
      * @param string $name Name of argument
@@ -55,14 +70,16 @@
      * @param string $description Description of argument
      * @param boolean $required TRUE if argument is required
      * @param mixed $defaultValue Default value
+     * @param bool|null $escape Whether or not argument is escaped, or uses default escaping behavior (see class var comment)
      */
-    public function __construct($name, $type, $description, $required, $defaultValue = null)
+    public function __construct($name, $type, $description, $required, $defaultValue = null, $escape = null)
     {
         $this->name = $name;
         $this->type = $type;
         $this->description = $description;
         $this->required = $required;
         $this->defaultValue = $defaultValue;
+        $this->escape = $escape;
     }
 
     /**
@@ -114,4 +131,12 @@
     {
         return $this->defaultValue;
     }
+
+    /**
+     * @return bool|null
+     */
+    public function getEscape()
+    {
+        return $this->escape;
+    }
 }
```
