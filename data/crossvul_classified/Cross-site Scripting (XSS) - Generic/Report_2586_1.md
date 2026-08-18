# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2586_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2586_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 10-50 of the vulnerable file.

        url = url.substr(1 + url.lastIndexOf("/"))
            .split('?')[0]
            .split('#')[0];
        return url.substr(1 + url.lastIndexOf("."))
    }

    function resolveImg(img) {
        var src = $(img).attr("src");
        if (src[0] == "/") {
            $(img).attr("src", src.substring(1));
        }
    }

    // Onload, take the DOM of the page, get the markdown formatted text out and
    // apply the converter.
    function makeHtml(data) {
        storage.get('mathjax', function(items) {
            // Convert MarkDown to HTML without MathJax typesetting.
            // This is done to make page responsiveness.  The HTML body
            // is replaced after MathJax typesetting.
            marked.setOptions(config.markedOptions);
            var html = marked(data);
            $(document.body).html(html);

            $('img').on("error", function() {
                resolveImg(this);
            });

            // Apply MathJax typesetting
            if (items.mathjax) {
                $.getScript(chrome.extension.getURL('js/marked.js'));
                $.getScript(chrome.extension.getURL('js/highlight.js'), function() {
                    $.getScript(chrome.extension.getURL('js/config.js'));
                });

                // Create hidden div to use for MathJax processing
                var mathjaxDiv = $("<div/>").attr("id", config.mathjaxProcessingElementId)
                                    .text(data)
                                    .hide();
                $(document.body).append(mathjaxDiv);
                $.getScript(chrome.extension.getURL('js/runMathJax.js'));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,6 +27,7 @@
             // Convert MarkDown to HTML without MathJax typesetting.
             // This is done to make page responsiveness.  The HTML body
             // is replaced after MathJax typesetting.
+            config.markedOptions.sanitize = items.mathjax ? false : true;
             marked.setOptions(config.markedOptions);
             var html = marked(data);
             $(document.body).html(html);
```
