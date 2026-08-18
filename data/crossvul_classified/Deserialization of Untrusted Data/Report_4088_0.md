# CrossVul Fix Pair: Deserialization of Untrusted Data in php
**Pair ID:** 4088_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4088_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```php
Lines 102-142 of the vulnerable file.

     * @param bool $handleFlexformSections Whether to handle flexform sections differently
     * @return bool Whether the submitted field change functions are valid
     */
    protected function areFieldChangeFunctionsValid($handleFlexformSections = false)
    {
        $result = false;
        if (isset($this->parameters['fieldChangeFunc']) && is_array($this->parameters['fieldChangeFunc']) && isset($this->parameters['fieldChangeFuncHash'])) {
            $matches = [];
            $pattern = '#\\[el\\]\\[(([^]-]+-[^]-]+-)(idx\\d+-)([^]]+))\\]#i';
            $fieldChangeFunctions = $this->parameters['fieldChangeFunc'];
            // Special handling of flexform sections:
            // Field change functions are modified in JavaScript, thus the hash is always invalid
            if ($handleFlexformSections && preg_match($pattern, $this->parameters['itemName'], $matches)) {
                $originalName = $matches[1];
                $cleanedName = $matches[2] . $matches[4];
                foreach ($fieldChangeFunctions as &$value) {
                    $value = str_replace($originalName, $cleanedName, $value);
                }
                unset($value);
            }
            $result = hash_equals(GeneralUtility::hmac(serialize($fieldChangeFunctions)), $this->parameters['fieldChangeFuncHash']);
        }
        return $result;
    }

    /**
     * Get attributes for the body tag
     *
     * @return string[] Array of body-tag attributes
     */
    protected function getBodyTagAttributes()
    {
        $formEngineParameters = [];
        $parameters = parent::getBodyTagAttributes();

        $formEngineParameters['fieldChangeFunc'] = $this->parameters['fieldChangeFunc'];
        $formEngineParameters['fieldChangeFuncHash'] = GeneralUtility::hmac(serialize($this->parameters['fieldChangeFunc']));

        $parameters['data-add-on-params'] .= HttpUtility::buildQueryString(['P' => $formEngineParameters], '&');

        return $parameters;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -119,7 +119,7 @@
                 }
                 unset($value);
             }
-            $result = hash_equals(GeneralUtility::hmac(serialize($fieldChangeFunctions)), $this->parameters['fieldChangeFuncHash']);
+            $result = hash_equals(GeneralUtility::hmac(serialize($fieldChangeFunctions), 'backend-link-browser'), $this->parameters['fieldChangeFuncHash']);
         }
         return $result;
     }
@@ -135,7 +135,7 @@
         $parameters = parent::getBodyTagAttributes();
 
         $formEngineParameters['fieldChangeFunc'] = $this->parameters['fieldChangeFunc'];
-        $formEngineParameters['fieldChangeFuncHash'] = GeneralUtility::hmac(serialize($this->parameters['fieldChangeFunc']));
+        $formEngineParameters['fieldChangeFuncHash'] = GeneralUtility::hmac(serialize($this->parameters['fieldChangeFunc']), 'backend-link-browser');
 
         $parameters['data-add-on-params'] .= HttpUtility::buildQueryString(['P' => $formEngineParameters], '&');
 
```
