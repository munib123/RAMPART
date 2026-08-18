# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1961_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1961_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1176-1216 of the vulnerable file.

    function _loadParams($aMergeArray = null, $clearParams = false)
    {
        // List of variables to get
        $aVarArray = array(
            'period_start',
            'period_end',
            'listorder',
            'orderdirection',
            'day',
            'period_preset',
            'setPerPage'
        );

        // Clear existing params, if required
        if ($clearParams) {
            unset($this->aPageParams);
        }

        // Add new params from $_GET/session
        foreach ($aVarArray as $k => $v) {
            $this->aPageParams[$v] = htmlspecialchars(MAX_getStoredValue($v, ''));
        }

        // Ensure the setPerPage value is set
        if (empty($this->aPageParams['setPerPage'])) {
            $this->aPageParams['setPerPage'] = 15;
        }

        // Merge params with optional array, if required
        if (is_array($aMergeArray)) {
            $this->aPageParams = array_merge($this->aPageParams, $aMergeArray);
        }

        // Ensure the orderdirection value is set
        if ($this->aPageParams['orderdirection'] == '') {
            $this->aPageParams['orderdirection'] = 'up';
        }

    }

    /**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1193,12 +1193,14 @@
 
         // Add new params from $_GET/session
         foreach ($aVarArray as $k => $v) {
-            $this->aPageParams[$v] = htmlspecialchars(MAX_getStoredValue($v, ''));
+            $this->aPageParams[$v] = htmlspecialchars(MAX_getStoredValue($v, ''), ENT_QUOTES);
         }
 
         // Ensure the setPerPage value is set
         if (empty($this->aPageParams['setPerPage'])) {
             $this->aPageParams['setPerPage'] = 15;
+        } else {
+            $this->aPageParams['setPerPage'] = (int) $this->aPageParams['setPerPage'];
         }
 
         // Merge params with optional array, if required
```
