# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1742_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1742_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 208-248 of the vulnerable file.

    function renderHeader(&$header)
    {
        $this->_ary['sections'][$this->_sectionCount] = array(
            'header' => $header->toHtml(),
            'name'   => $header->getName()
        );
        $this->_currentSection = $this->_sectionCount++;
    } // end func renderHeader


    function renderElement(&$element, $required, $error)
    {
        $elAry = $this->_elementToArray($element, $required, $error);
        if (!empty($error)) {
            $this->_ary['errors'][$elAry['name']] = $error;
        }
        $this->_storeArray($elAry);
    } // end func renderElement


    function renderHidden(&$element)
    {
        if ($this->_collectHidden) {
            $this->_ary['hidden'] .= $element->toHtml() . "\n";
        } else {
            $this->renderElement($element, false, null);
        }
    } // end func renderHidden


    function startGroup(&$group, $required, $error)
    {
        $this->_currentGroup = $this->_elementToArray($group, $required, $error);
        if (!empty($error)) {
            $this->_ary['errors'][$this->_currentGroup['name']] = $error;
        }
    } // end func startGroup


    function finishGroup(&$group)
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -225,12 +225,15 @@
     } // end func renderElement
 
 
-    function renderHidden(&$element)
+    function renderHidden(&$element, $required, $error)
     {
         if ($this->_collectHidden) {
             $this->_ary['hidden'] .= $element->toHtml() . "\n";
         } else {
             $this->renderElement($element, false, null);
+        }
+        if (!empty($error)) {
+            $this->_ary['errors'][$elAry['name']] = $error;
         }
     } // end func renderHidden
 
```
