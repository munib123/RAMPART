# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5100_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5100_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 92-132 of the vulnerable file.

            ? $dom->returnHtml()
            : $dom->returnBody();
    }

    /**
     * Process DOM node.
     *
     * @param DOMElement $node  Element node.
     *
     * @return string  The plaintext representation.
     */
    protected function _node($node)
    {
        if ($node instanceof DOMElement) {
            $remove = $this->_params['strip_style_attributes']
                ? array('style')
                : array();

            switch (Horde_String::lower($node->tagName)) {
            case 'a':
                /* Strip out data URLs living in an A HREF element
                 * (Bug #8715). */
                if ($node->hasAttribute('href') &&
                    preg_match("/\s*data:/i", $node->getAttribute('href'))) {
                    $remove[] = 'href';
                }
                break;

            case 'applet':
            case 'audio':
            case 'bgsound':
            case 'embed':
            case 'iframe':
            case 'import':
            case 'java':
            case 'layer':
            case 'meta':
            case 'object':
            case 'script':
            case 'video':
            case 'xml':
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -109,11 +109,19 @@
 
             switch (Horde_String::lower($node->tagName)) {
             case 'a':
-                /* Strip out data URLs living in an A HREF element
+            case 'form':
+                /* Strip out data URLs living in link-like elements
                  * (Bug #8715). */
-                if ($node->hasAttribute('href') &&
-                    preg_match("/\s*data:/i", $node->getAttribute('href'))) {
-                    $remove[] = 'href';
+                if (Horde_String::lower($node->tagName) == 'form') {
+                    $attributes = array('action');
+                } else {
+                    $attributes = array('href', 'xlink:href');
+                }
+                foreach ($attributes as $attribute) {
+                    if ($node->hasAttribute($attribute) &&
+                        preg_match("/\s*data:/i", $node->getAttribute($attribute))) {
+                        $remove[] = $attribute;
+                    }
                 }
                 break;
 
```
