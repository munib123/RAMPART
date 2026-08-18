# CrossVul Fix Pair: Deserialization of Untrusted Data in php
**Pair ID:** 4088_1
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4088_1`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```php
Lines 61-101 of the vulnerable file.

                    . $this->data['flexFormSheetName']
                    . '/ROOT/el/'
                    . $this->data['flexFormFieldName']
                    . '/el/'
                    . $this->data['flexFormContainerName']
                    . '/el/'
                    . $this->data['flexFormContainerFieldName']
                    . '/TCEforms/config';
            }
        }

        $urlParameters = [
            'P' => [
                'table' => $this->data['tableName'],
                'field' => $this->data['fieldName'],
                'formName' => 'editform',
                'flexFormDataStructureIdentifier' => $flexFormDataStructureIdentifier,
                'flexFormDataStructurePath' => $flexFormDataStructurePath,
                'hmac' => GeneralUtility::hmac('editform' . $itemName, 'wizard_js'),
                'fieldChangeFunc' => $parameterArray['fieldChangeFunc'],
                'fieldChangeFuncHash' => GeneralUtility::hmac(serialize($parameterArray['fieldChangeFunc'])),
            ],
        ];
        $uriBuilder = GeneralUtility::makeInstance(UriBuilder::class);
        $url = (string)$uriBuilder->buildUriFromRoute('wizard_edit', $urlParameters);

        $id = StringUtility::getUniqueId('t3js-formengine-fieldcontrol-');

        return [
            'iconIdentifier' => 'actions-open',
            'title' => $title,
            'linkAttributes' => [
                'id' => htmlspecialchars($id),
                'href' => $url,
                'data-element' => $itemName,
                'data-window-parameters' => $windowOpenParameters,
            ],
            'requireJsModules' => [
                ['TYPO3/CMS/Backend/FormEngine/FieldControl/EditPopup' => 'function(FieldControl) {new FieldControl(' . GeneralUtility::quoteJSvalue('#' . $id) . ');}'],
            ],
        ];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,7 +78,7 @@
                 'flexFormDataStructurePath' => $flexFormDataStructurePath,
                 'hmac' => GeneralUtility::hmac('editform' . $itemName, 'wizard_js'),
                 'fieldChangeFunc' => $parameterArray['fieldChangeFunc'],
-                'fieldChangeFuncHash' => GeneralUtility::hmac(serialize($parameterArray['fieldChangeFunc'])),
+                'fieldChangeFuncHash' => GeneralUtility::hmac(serialize($parameterArray['fieldChangeFunc']), 'backend-link-browser'),
             ],
         ];
         $uriBuilder = GeneralUtility::makeInstance(UriBuilder::class);
```
