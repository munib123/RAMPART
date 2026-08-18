# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4399_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4399_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 127-167 of the vulnerable file.

    
    function formatSearchMetric(count, searchterm) {
        if (count == 1) {
            return count + " search result for '" + searchterm + "':";
        } else if (count == 0) {
            return "No search results for '" + searchterm + "'.";
        } else {
            return count + " search results for '" + searchterm + "':";
        }
    }
    
    function formatSearchResult(result, searchterms) {
        var teaser = makeTeaser(escapeHTML(result.doc.body), searchterms);
        teaser_count++;

        // The ?URL_MARK_PARAM= parameter belongs inbetween the page and the #heading-anchor
        var url = doc_urls[result.ref].split("#");
        if (url.length == 1) { // no anchor found
            url.push("");
        }

        return '<a href="' + path_to_root + url[0] + '?' + URL_MARK_PARAM + '=' + searchterms + '#' + url[1]
            + '" aria-details="teaser_' + teaser_count + '">' + result.doc.breadcrumbs + '</a>'
            + '<span class="teaser" id="teaser_' + teaser_count + '" aria-label="Search Result Teaser">' 
            + teaser + '</span>';
    }
    
    function makeTeaser(body, searchterms) {
        // The strategy is as follows:
        // First, assign a value to each word in the document:
        //  Words that correspond to search terms (stemmer aware): 40
        //  Normal words: 2
        //  First word in a sentence: 8
        // Then use a sliding window with a constant number of words and count the
        // sum of the values of the words within the window. Then use the window that got the
        // maximum sum. If there are multiple maximas, then get the last one.
        // Enclose the terms in <em>.
        var stemmed_searchterms = searchterms.map(function(w) {
            return elasticlunr.stemmer(w.toLowerCase());
        });
        var searchterm_weight = 40;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -144,6 +144,11 @@
         if (url.length == 1) { // no anchor found
             url.push("");
         }
+
+        // encodeURIComponent escapes all chars that could allow an XSS except
+        // for '. Due to that we also manually replace ' with its url-encoded
+        // representation (%27).
+        var searchterms = encodeURIComponent(searchterms.join(" ")).replace(/\'/g, "%27");
 
         return '<a href="' + path_to_root + url[0] + '?' + URL_MARK_PARAM + '=' + searchterms + '#' + url[1]
             + '" aria-details="teaser_' + teaser_count + '">' + result.doc.breadcrumbs + '</a>'
```
