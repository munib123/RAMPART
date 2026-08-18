# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4571_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4571_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 213-238 of the vulnerable file.

    {
        Tools::displayAsDeprecated('Use getExtendedMessage instead');

        return $this->getExtendedMessage($html);
    }

    /**
     * Return the content of the Exception.
     *
     * @return string content of the exception
     */
    protected function getExtendedMessage($html = true)
    {
        $format = '<p><b>%s</b><br /><i>at line </i><b>%d</b><i> in file </i><b>%s</b></p>';
        if (!$html) {
            $format = strip_tags(str_replace('<br />', ' ', $format));
        }

        return sprintf(
            $format,
            $this->getMessage(),
            $this->getLine(),
            ltrim(str_replace(array(_PS_ROOT_DIR_, '\\'), array('', '/'), $this->getFile()), '/')
        );
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -230,7 +230,7 @@
 
         return sprintf(
             $format,
-            $this->getMessage(),
+            Tools::safeOutput($this->getMessage(), true),
             $this->getLine(),
             ltrim(str_replace(array(_PS_ROOT_DIR_, '\\'), array('', '/'), $this->getFile()), '/')
         );
```
