# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 4035_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4035_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 40-82 of the vulnerable file.

    public function getAllValues($mElement = null, $bSearchInFunctionArguments = false) {
        $sSearchString = null;
        if ($mElement === null) {
            $mElement = $this;
        } else if (is_string($mElement)) {
            $sSearchString = $mElement;
            $mElement = $this;
        }
        $aResult = array();
        $this->allValues($mElement, $aResult, $sSearchString, $bSearchInFunctionArguments);
        return $aResult;
    }

    /**
     * Returns all Selector objects found recursively in the tree.
     * Note that this does not yield the full DeclarationBlock that the selector belongs to (and, currently, there is no way to get to that).
     * @param $sSpecificitySearch An optional filter by specificity. May contain a comparison operator and a number or just a number (defaults to "==").
     * @example getSelectorsBySpecificity('>= 100')
     */
    public function getSelectorsBySpecificity($sSpecificitySearch = null) {
        if (is_numeric($sSpecificitySearch) || is_numeric($sSpecificitySearch[0])) {
            $sSpecificitySearch = "== $sSpecificitySearch";
        }
        $aResult = array();
        $this->allSelectors($aResult, $sSpecificitySearch);
        return $aResult;
    }

    /**
     * Expands all shorthand properties to their long value
     */
    public function expandShorthands() {
        foreach ($this->getAllDeclarationBlocks() as $oDeclaration) {
            $oDeclaration->expandShorthands();
        }
    }

    /*
     * Create shorthands properties whenever possible
     */

    public function createShorthands() {
        foreach ($this->getAllDeclarationBlocks() as $oDeclaration) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,9 +57,6 @@
      * @example getSelectorsBySpecificity('>= 100')
      */
     public function getSelectorsBySpecificity($sSpecificitySearch = null) {
-        if (is_numeric($sSpecificitySearch) || is_numeric($sSpecificitySearch[0])) {
-            $sSpecificitySearch = "== $sSpecificitySearch";
-        }
         $aResult = array();
         $this->allSelectors($aResult, $sSpecificitySearch);
         return $aResult;
```
