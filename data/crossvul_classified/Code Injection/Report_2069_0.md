# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 2069_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2069_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 44-84 of the vulnerable file.

     * @var array
     */
    protected $_vars;

    /**
     * Returns a Horde_Variables object populated with the form input.
     *
     * @param string $sanitize  Sanitize the input variables?
     *
     * @return Horde_Variables  Variables object.
     */
    static public function getDefaultVariables($sanitize = false)
    {
        return new self(null, $sanitize);
    }

    /**
     * Constructor.
     *
     * @param array $vars       The list of form variables (if null, defaults
     *                          to PHP's $_REQUEST value).
     * @param string $sanitize  Sanitize the input variables?
     */
    public function __construct($vars = array(), $sanitize = false)
    {
        if (is_null($vars)) {
            $request_copy = $_REQUEST;
            $vars = Horde_Util::dispelMagicQuotes($request_copy);
        }

        if (isset($vars['_formvars'])) {
            $this->_expected = @unserialize($vars['_formvars']);
            unset($vars['_formvars']);
        }

        $this->_vars = $vars;

        if ($sanitize) {
            $this->sanitize();
        }
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,7 +61,9 @@
      * Constructor.
      *
      * @param array $vars       The list of form variables (if null, defaults
-     *                          to PHP's $_REQUEST value).
+     *                          to PHP's $_REQUEST value). If '_formvars'
+     *                          exists, it must be a JSON encoded array that
+     *                          contains the list of allowed form variables.
      * @param string $sanitize  Sanitize the input variables?
      */
     public function __construct($vars = array(), $sanitize = false)
@@ -72,7 +74,7 @@
         }
 
         if (isset($vars['_formvars'])) {
-            $this->_expected = @unserialize($vars['_formvars']);
+            $this->_expected = @json_decode($vars['_formvars'], true);
             unset($vars['_formvars']);
         }
 
```
