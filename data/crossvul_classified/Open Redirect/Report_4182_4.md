# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in php
**Pair ID:** 4182_4
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4182_4`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```php
Lines 201-241 of the vulnerable file.

                    'This `f:else` was rendered',
                    'The value was "3"',
                    'The unmatched value case triggered',
                    'The "b" nested switch case was triggered'
                ]
            ],
            'example_variables.php' => [
                'example_variables.php',
                [
                    'Simple variable: string foo',
                    'A string with numbers in it: 132',
                    'Ditto, with type name stored in variable: 132',
                    'A comma-separated value iterated as array:' . "\n\t- one\n\t- two",
                    'String variable name with dynamic1 part: String using $dynamic1.',
                    'String variable name with dynamic2 part: String using $dynamic2.',
                    'Array member in $array[$dynamic1]: Dynamic key in $array[$dynamic1]',
                    'Array member in $array[$dynamic2]: Dynamic key in $array[$dynamic2]',
                    'Output of variable whose name is stored in a variable: string foo',
                    'Direct access of numeric prefixed variable: Numeric prefixed variable',
                    'Aliased access of numeric prefixed variable: Numeric prefixed variable',
                    'Received $array.foobar with value <b>Unescaped string</b> (same using "value" argument: <b>Unescaped string</b>)',
                    'Received $array.printf with formatted string Formatted string, value: formatted',
                    'Received $array.baz with value 42',
                    'Received $array.xyz.foobar with value Escaped sub-string',
                    'Received $myVariable with value Nice string'
                ]
            ],
            'example_variableprovider.php' => [
                'example_variableprovider.php',
                [
                    'VariableProvider template from Singles.',
                    'Random: random',
                ]
            ],
            'example_dynamiclayout.php' => [
                'example_dynamiclayout.php',
                [
                    'Rendered via DynamicLayout, section "Main":',
                ]
            ],
            'example_cachestatic.php' => [
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -218,6 +218,8 @@
                     'Output of variable whose name is stored in a variable: string foo',
                     'Direct access of numeric prefixed variable: Numeric prefixed variable',
                     'Aliased access of numeric prefixed variable: Numeric prefixed variable',
+                    'Escaped ternary expression: &lt;b&gt;Unescaped string&lt;/b&gt;',
+                    'Escaped cast expression: &lt;b&gt;Unescaped string&lt;/b&gt;',
                     'Received $array.foobar with value <b>Unescaped string</b> (same using "value" argument: <b>Unescaped string</b>)',
                     'Received $array.printf with formatted string Formatted string, value: formatted',
                     'Received $array.baz with value 42',
@@ -260,7 +262,7 @@
                     'ViewHelper error: Undeclared arguments passed to ViewHelper TYPO3Fluid\Fluid\ViewHelpers\IfViewHelper: notregistered. Valid arguments are: then, else, condition - Offending code: <f:if notregistered="1" />',
                     'Parser error: The ViewHelper "<f:invalid>" could not be resolved.',
                     'Based on your spelling, the system would load the class "TYPO3Fluid\Fluid\ViewHelpers\InvalidViewHelper", however this class does not exist. Offending code: <f:invalid />',
-                    'Invalid expression: Invalid target conversion type "invalidtype" specified in casting expression "{foobar as invalidtype}".',
+                    'Invalid expression: Invalid target conversion type &quot;invalidtype&quot; specified in casting expression &quot;{foobar as invalidtype}&quot;.',
                 ]
             ]
         ];
```
