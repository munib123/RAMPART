# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2380_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2380_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 229-269 of the vulnerable file.

        // create form
        $this->frm = new FrontendForm('search', null, 'get', null, false);

        // could also have been submitted by our widget
        if (!\SpoonFilter::getGetValue('q', null, '')) {
            $_GET['q'] = \SpoonFilter::getGetValue('q_widget', null, '');
        }

        // create elements
        $this->frm->addText(
            'q',
            null,
            255,
            'inputText liveSuggest autoComplete',
            'inputTextError liveSuggest autoComplete'
        );

        // since we know the term just here we should set the canonical url here
        $canonicalUrl = SITE_URL . FrontendNavigation::getURLForBlock('Search');
        if (isset($_GET['q']) && $_GET['q'] != '') {
            $canonicalUrl .= '?q=' . $_GET['q'];
        }
        $this->header->setCanonicalUrl($canonicalUrl);
    }

    /**
     * Parse the data into the template
     */
    private function parse()
    {
        // parse the form
        $this->frm->parse($this->tpl);

        // no search term = no search
        if (!$this->term) {
            return;
        }

        // assign articles
        $this->tpl->assign('searchResults', $this->items);
        $this->tpl->assign('searchTerm', $this->term);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -246,7 +246,7 @@
         // since we know the term just here we should set the canonical url here
         $canonicalUrl = SITE_URL . FrontendNavigation::getURLForBlock('Search');
         if (isset($_GET['q']) && $_GET['q'] != '') {
-            $canonicalUrl .= '?q=' . $_GET['q'];
+            $canonicalUrl .= '?q=' . \SpoonFilter::htmlspecialchars($_GET['q']);
         }
         $this->header->setCanonicalUrl($canonicalUrl);
     }
```
