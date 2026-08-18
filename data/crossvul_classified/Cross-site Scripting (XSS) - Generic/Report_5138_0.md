# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5138_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5138_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1883-1923 of the vulnerable file.

        $currentSearchId = null;
        $currentSearchName = null;
        if (null != $currentSearch) {
            $currentSearchId = $currentSearch->getId();
            $currentSearchName = $currentSearch->getSearchName();
        }

        foreach ($this->_savedSearchList as $id => $name) {
            $html_output .= '<option value="' . htmlspecialchars($id)
                . '" ' . (
                $id == $currentSearchId
                    ? 'selected="selected" '
                    : ''
                )
                . '>'
                . htmlspecialchars($name)
                . '</option>';
        }
        $html_output .= '</select>';
        $html_output .= '<input type="text" name="searchName" id="searchName" '
            . 'value="' . $currentSearchName . '" />';
        $html_output .= '<input type="hidden" name="action" id="action" value="" />';
        $html_output .= '<input type="submit" name="saveSearch" id="saveSearch" '
            . 'value="' . __('Create bookmark') . '" />';
        if (null !== $currentSearchId) {
            $html_output .= '<input type="submit" name="updateSearch" '
                . 'id="updateSearch" value="' . __('Update bookmark') . '" />';
            $html_output .= '<input type="submit" name="deleteSearch" '
                . 'id="deleteSearch" value="' . __('Delete bookmark') . '" />';
        }

        return $html_output;
    }

    /**
     * Initialize _criteria_column_count
     *
     * @return int Previous number of columns
     */
    private function _initializeCriteriasCount()
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1900,7 +1900,7 @@
         }
         $html_output .= '</select>';
         $html_output .= '<input type="text" name="searchName" id="searchName" '
-            . 'value="' . $currentSearchName . '" />';
+            . 'value="' . htmlspecialchars($currentSearchName) . '" />';
         $html_output .= '<input type="hidden" name="action" id="action" value="" />';
         $html_output .= '<input type="submit" name="saveSearch" id="saveSearch" '
             . 'value="' . __('Create bookmark') . '" />';
```
