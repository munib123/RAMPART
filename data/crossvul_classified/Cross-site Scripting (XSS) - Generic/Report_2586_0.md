# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2586_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2586_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-33 of the vulnerable file.

window.config = (function(hljs) {
    // Define module
    var module = {};

    // Private module properties
    var latexDelimitersEnabled = false;

    // Public module properties
    module.markedOptions = {
        gfm: true,
        tables: true,
        breaks: false,
        highlight: function(code) {
            return hljs.highlightAuto(code).value;
        }
    };

    module.mathjaxProcessingElementId = "mathjaxProcessing";

    // Note: when math delimiters are set in JS as strings, backslashes need
    // to be escaped
    module.mathjaxConfig = {
        tex2jax: {
            inlineMath: [ ['\\\\(', '\\\\)'] ],
            displayMath: [ ['$$', '$$'], ['\\\\[', '\\\\]'] ],
            processEscapes: false
        }
    };

    // Public module functions
    module.enableLatexDelimiters = function() {
        if (!latexDelimitersEnabled) {
            // Note: when math delimiters are set in JS as strings,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,6 +10,7 @@
         gfm: true,
         tables: true,
         breaks: false,
+        sanitize: true,
         highlight: function(code) {
             return hljs.highlightAuto(code).value;
         }
```
