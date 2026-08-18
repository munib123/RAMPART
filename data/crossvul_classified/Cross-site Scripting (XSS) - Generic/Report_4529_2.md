# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4529_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4529_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 8-48 of the vulnerable file.

            cleanup();
        });

        jsc.property(
            'displays & hides data as requested',
            common.jscMimeTypes(),
            'string',
            'string',
            'string',
            'string',
            function (mimeType, rawdata, filename, prefix, postfix) {
                var clean = jsdom(),
                    data = 'data:' + mimeType + ';base64,' + btoa(rawdata),
                    previewSupported = (
                        mimeType.substring(0, 6) === 'image/' ||
                        mimeType.substring(0, 6) === 'audio/' ||
                        mimeType.substring(0, 6) === 'video/' ||
                        mimeType.match(/\/pdf/i)
                    ),
                    results = [];
                prefix = prefix.replace(/%(s|d)/g, '%%');
                postfix = postfix.replace(/%(s|d)/g, '%%');
                $('body').html(
                    '<div id="attachment" role="alert" class="hidden alert ' +
                    'alert-info"><span class="glyphicon glyphicon-download-' +
                    'alt" aria-hidden="true"></span> <a class="alert-link">' +
                    'Download attachment</a></div><div id="attachmentPrevie' +
                    'w" class="hidden"></div>'
                );
                // mock createObjectURL for jsDOM
                if (typeof window.URL.createObjectURL === 'undefined') {
                    Object.defineProperty(
                        window.URL,
                        'createObjectURL',
                        {value: function(blob) {
                            return 'blob:' + location.origin + '/1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed';
                        }}
                    )
                }
                $.PrivateBin.AttachmentViewer.init();
                results.push(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,7 @@
                         mimeType.match(/\/pdf/i)
                     ),
                     results = [];
-                prefix = prefix.replace(/%(s|d)/g, '%%');
+                prefix  = prefix.replace(/%(s|d)/g, '%%');
                 postfix = postfix.replace(/%(s|d)/g, '%%');
                 $('body').html(
                     '<div id="attachment" role="alert" class="hidden alert ' +
@@ -90,7 +90,7 @@
                     results.push(
                         element.children()[0].href === data &&
                         element.children()[0].getAttribute('download') === filename &&
-                        element.children()[0].text === prefix + filename + postfix
+                        element.children()[0].text === $('<div />').text(prefix + filename + postfix).html()
                     );
                 } else {
                     results.push(element.children()[0].href === data);
```
