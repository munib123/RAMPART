# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 5156_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5156_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 770-797 of the vulnerable file.

});

/**
 * Attach a generic event handler to clicks
 * on pages and submissions of forms
 */
$(document).on('click', 'a', AJAX.requestHandler);
$(document).on('submit', 'form', AJAX.requestHandler);

/**
 * Gracefully handle fatal server errors
 * (e.g: 500 - Internal server error)
 */
$(document).ajaxError(function (event, request, settings) {
    if (request.status !== 0) { // Don't handle aborted requests
        var errorCode = PMA_sprintf(PMA_messages.strErrorCode, request.status);
        var errorText = PMA_sprintf(PMA_messages.strErrorText, request.statusText);
        PMA_ajaxShowMessage(
            '<div class="error">' +
            PMA_messages.strErrorProcessingRequest +
            '<div>' + errorCode + '</div>' +
            '<div>' + errorText + '</div>' +
            '</div>',
            false
        );
        AJAX.active = false;
    }
});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -787,8 +787,8 @@
         PMA_ajaxShowMessage(
             '<div class="error">' +
             PMA_messages.strErrorProcessingRequest +
-            '<div>' + errorCode + '</div>' +
-            '<div>' + errorText + '</div>' +
+            '<div>' + escapeHtml(errorCode) + '</div>' +
+            '<div>' + escapeHtml(errorText) + '</div>' +
             '</div>',
             false
         );
```
