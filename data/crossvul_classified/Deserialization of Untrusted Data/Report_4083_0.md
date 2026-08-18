# CrossVul Fix Pair: Deserialization of Untrusted Data in php
**Pair ID:** 4083_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4083_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```php
Lines 1-33 of the vulnerable file.

<?php
/**
 * This file is part of the TYPO3 CMS project.
 *
 * It is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, either version 2
 * of the License, or any later version.
 *
 * For the full copyright and license information, please read the
 * LICENSE.txt file that was distributed with this source code.
 *
 * The TYPO3 project - inspiring people to share!
 */

call_user_func(function() {
    $value = \TYPO3\CMS\Core\Utility\GeneralUtility::_GET('value');
    $addition = \TYPO3\CMS\Core\Utility\GeneralUtility::_GET('addition');
    $scope = \TYPO3\CMS\Core\Utility\GeneralUtility::_GET('scope');

    $content = \TYPO3\CMS\Core\Utility\GeneralUtility::hmac($value, $addition);

    if ($scope === 'flashvars') {
        header('Content-type: application/x-www-form-urlencoded');
        $content = 'hash=' . $content;
    } else {
        header('Content-type: text/plain');
    }

    header('Pragma: no-cache');
    header('Cache-control: no-cache');

    echo $content;
});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,10 +14,15 @@
 
 call_user_func(function() {
     $value = \TYPO3\CMS\Core\Utility\GeneralUtility::_GET('value');
-    $addition = \TYPO3\CMS\Core\Utility\GeneralUtility::_GET('addition');
     $scope = \TYPO3\CMS\Core\Utility\GeneralUtility::_GET('scope');
 
-    $content = \TYPO3\CMS\Core\Utility\GeneralUtility::hmac($value, $addition);
+    if (!is_string($value) || empty($value)) {
+        \TYPO3\CMS\Core\Utility\HttpUtility::setResponseCodeAndExit(
+            \TYPO3\CMS\Core\Utility\HttpUtility::HTTP_STATUS_400
+        );
+    }
+
+    $content = \TYPO3\CMS\Core\Utility\GeneralUtility::hmac($value, 'flashvars');
 
     if ($scope === 'flashvars') {
         header('Content-type: application/x-www-form-urlencoded');
```
