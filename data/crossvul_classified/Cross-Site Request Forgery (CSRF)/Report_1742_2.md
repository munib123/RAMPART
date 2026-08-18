# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1742_2
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1742_2`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 62-93 of the vulnerable file.

    // {{{ freeze()

    /**
     * Freeze the element so that only its value is returned
     *
     * @access    public
     * @return    void
     */
    function freeze()
    {
        return false;
    } //end func freeze

    // }}}
    // {{{ accept()

   /**
    * Accepts a renderer
    *
    * @param HTML_QuickForm_Renderer    renderer object
    * @access public
    * @return void
    */
    function accept(&$renderer)
    {
        $renderer->renderHidden($this);
    } // end func accept

    // }}}

} //end class HTML_QuickForm_hidden
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -79,12 +79,14 @@
     * Accepts a renderer
     *
     * @param HTML_QuickForm_Renderer    renderer object
+    * @param bool                       Whether an element is required
+    * @param string                     An error message associated with an element
     * @access public
     * @return void
     */
-    function accept(&$renderer)
+    function accept(&$renderer, $required=false, $error=null)
     {
-        $renderer->renderHidden($this);
+        $renderer->renderHidden($this, $required, $error);
     } // end func accept
 
     // }}}
```
