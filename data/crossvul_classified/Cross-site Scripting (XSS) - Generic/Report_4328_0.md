# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4328_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4328_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 279-319 of the vulnerable file.

    /**
     * Escape script tags within HTML content.
     */
    protected function escapeScripts(string $html) : string
    {
        if (empty($html)) {
            return $html;
        }

        libxml_use_internal_errors(true);
        $doc = new DOMDocument();
        $doc->loadHTML(mb_convert_encoding($html, 'HTML-ENTITIES', 'UTF-8'));
        $xPath = new DOMXPath($doc);

        // Remove standard script tags
        $scriptElems = $xPath->query('//script');
        foreach ($scriptElems as $scriptElem) {
            $scriptElem->parentNode->removeChild($scriptElem);
        }

        // Remove data or JavaScript iFrames
        $badIframes = $xPath->query('//*[contains(@src, \'data:\')] | //*[contains(@src, \'javascript:\')] | //*[@srcdoc]');
        foreach ($badIframes as $badIframe) {
            $badIframe->parentNode->removeChild($badIframe);
        }

        // Remove 'on*' attributes
        $onAttributes = $xPath->query('//@*[starts-with(name(), \'on\')]');
        foreach ($onAttributes as $attr) {
            /** @var \DOMAttr $attr*/
            $attrName = $attr->nodeName;
            $attr->parentNode->removeAttribute($attrName);
        }

        $html = '';
        $topElems = $doc->documentElement->childNodes->item(0)->childNodes;
        foreach ($topElems as $child) {
            $html .= $doc->saveHTML($child);
        }

        return $html;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -296,6 +296,24 @@
             $scriptElem->parentNode->removeChild($scriptElem);
         }
 
+        // Remove clickable links to JavaScript URI
+        $badLinks = $xPath->query('//*[contains(@href, \'javascript:\')]');
+        foreach ($badLinks as $badLink) {
+            $badLink->parentNode->removeChild($badLink);
+        }
+
+        // Remove forms with calls to JavaScript URI
+        $badForms = $xPath->query('//*[contains(@action, \'javascript:\')] | //*[contains(@formaction, \'javascript:\')]');
+        foreach ($badForms as $badForm) {
+            $badForm->parentNode->removeChild($badForm);
+        }
+
+        // Remove meta tag to prevent external redirects
+        $metaTags = $xPath->query('//meta[contains(@content, \'url\')]');
+        foreach ($metaTags as $metaTag) {
+            $metaTag->parentNode->removeChild($metaTag);
+        }
+
         // Remove data or JavaScript iFrames
         $badIframes = $xPath->query('//*[contains(@src, \'data:\')] | //*[contains(@src, \'javascript:\')] | //*[@srcdoc]');
         foreach ($badIframes as $badIframe) {
```
