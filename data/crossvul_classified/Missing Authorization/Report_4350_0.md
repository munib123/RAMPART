# CrossVul Fix Pair: Missing Authorization in php
**Pair ID:** 4350_0
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4350_0`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 3-43 of the vulnerable file.

use Twig\Markup;
use Twig\Template;
use Twig\Sandbox\SecurityPolicyInterface;
use Twig\Sandbox\SecurityNotAllowedMethodError;
use Twig\Sandbox\SecurityNotAllowedPropertyError;

/**
 * SecurityPolicy globally blocks accessibility of certain methods and properties.
 *
 * @package october\system
 * @author Alexey Bobkov, Samuel Georges, Luke Towers
 */
final class SecurityPolicy implements SecurityPolicyInterface
{
    /**
     * @var array List of forbidden methods.
     */
    protected $blockedMethods = [
        'addDynamicMethod',
        'addDynamicProperty',
    ];

    /**
     * Constructor
     */
    public function __construct()
    {
        foreach ($this->blockedMethods as $i => $m) {
            $this->blockedMethods[$i] = strtolower($m);
        }
    }

    /**
     * Check the provided arguments against this security policy
     *
     * @param array $tags Array of tags to be checked against the policy ['tag', 'tag2', 'etc']
     * @param array $filters Array of filters to be checked against the policy ['filter', 'filter2', 'etc']
     * @param array $functions Array of funtions to be checked against the policy ['function', 'function2', 'etc']
     * @throws SecurityNotAllowedTagError if a given tag is not allowed
     * @throws SecurityNotAllowedFilterError if a given filter is not allowed
     * @throws SecurityNotAllowedFunctionError if a given function is not allowed
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,6 +20,8 @@
     protected $blockedMethods = [
         'addDynamicMethod',
         'addDynamicProperty',
+        'bindEvent',
+        'bindEventOnce',
     ];
 
     /**
```
