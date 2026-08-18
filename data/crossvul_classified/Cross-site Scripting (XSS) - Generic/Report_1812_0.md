# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1812_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1812_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 31-71 of the vulnerable file.

                       $var->isDisabled() ? ' disabled="disabled" ' : '',
                       $this->_getActionScripts($form, $var)
               );
    }

    protected function _renderVarInput_number($form, &$var, &$vars)
    {
        $value = $var->getValue($vars);
        if ($var->type->getProperty('fraction')) {
            $value = sprintf('%01.' . $var->type->getProperty('fraction') . 'f', $value);
        }
        $linfo = Horde_Nls::getLocaleInfo();
        /* Only if there is a mon_decimal_point do the
         * substitution. */
        if (!empty($linfo['mon_decimal_point'])) {
            $value = str_replace('.', $linfo['mon_decimal_point'], $value);
        }
        return sprintf('<input type="text" size="5" name="%s" id="%s" value="%s"%s />',
                       htmlspecialchars($var->getVarName()),
                       $this->_genID($var->getVarName(), false),
                       $value,
                       $this->_getActionScripts($form, $var)
               );
    }

    protected function _renderVarInput_int($form, &$var, &$vars)
    {
        return sprintf('<input type="number" size="5" name="%s" id="%s" value="%s"%s />',
                       htmlspecialchars($var->getVarName()),
                       $this->_genID($var->getVarName(), false),
                       htmlspecialchars($var->getValue($vars)),
                       $this->_getActionScripts($form, $var)
               );
    }

    protected function _renderVarInput_octal($form, &$var, &$vars)
    {
        return sprintf('<input type="text" size="5" name="%s" id="%s" value="%s"%s />',
                       htmlspecialchars($var->getVarName()),
                       $this->_genID($var->getVarName(), false),
                       sprintf('0%o', octdec($var->getValue($vars))),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,7 +48,7 @@
         return sprintf('<input type="text" size="5" name="%s" id="%s" value="%s"%s />',
                        htmlspecialchars($var->getVarName()),
                        $this->_genID($var->getVarName(), false),
-                       $value,
+                       htmlspecialchars($value),
                        $this->_getActionScripts($form, $var)
                );
     }
```
