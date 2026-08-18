# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 4035_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4035_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 48-78 of the vulnerable file.

		} else if ($oElement instanceof ValueList) {
			if ($bSearchInFunctionArguments || !($oElement instanceof CSSFunction)) {
				foreach ($oElement->getListComponents() as $mComponent) {
					$this->allValues($mComponent, $aResult, $sSearchString, $bSearchInFunctionArguments);
				}
			}
		} else {
			//Non-List Value or String (CSS identifier)
			$aResult[] = $oElement;
		}
	}

	protected function allSelectors(&$aResult, $sSpecificitySearch = null) {
		$aDeclarationBlocks = array();
		$this->allDeclarationBlocks($aDeclarationBlocks);
		foreach ($aDeclarationBlocks as $oBlock) {
			foreach ($oBlock->getSelectors() as $oSelector) {
				if ($sSpecificitySearch === null) {
					$aResult[] = $oSelector;
				} else {
					$sComparison = "\$bRes = {$oSelector->getSpecificity()} $sSpecificitySearch;";
					eval($sComparison);
					if ($bRes) {
						$aResult[] = $oSelector;
					}
				}
			}
		}
	}

}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,9 +65,34 @@
 				if ($sSpecificitySearch === null) {
 					$aResult[] = $oSelector;
 				} else {
-					$sComparison = "\$bRes = {$oSelector->getSpecificity()} $sSpecificitySearch;";
-					eval($sComparison);
-					if ($bRes) {
+					$sComparator = '===';
+					$aSpecificitySearch = explode(' ', $sSpecificitySearch);
+					$iTargetSpecificity = $aSpecificitySearch[0];
+					if(count($aSpecificitySearch) > 1) {
+						$sComparator = $aSpecificitySearch[0];
+						$iTargetSpecificity = $aSpecificitySearch[1];
+					}
+					$iTargetSpecificity = (int)$iTargetSpecificity;
+					$iSelectorSpecificity = $oSelector->getSpecificity();
+					$bMatches = false;
+					switch($sComparator) {
+						case '<=':
+							$bMatches = $iSelectorSpecificity <= $iTargetSpecificity;
+						break;
+						case '<':
+							$bMatches = $iSelectorSpecificity < $iTargetSpecificity;
+						break;
+						case '>=':
+							$bMatches = $iSelectorSpecificity >= $iTargetSpecificity;
+						break;
+						case '>':
+							$bMatches = $iSelectorSpecificity > $iTargetSpecificity;
+						break;
+						default:
+							$bMatches = $iSelectorSpecificity === $iTargetSpecificity;
+						break;
+					}
+					if ($bMatches) {
 						$aResult[] = $oSelector;
 					}
 				}
```
