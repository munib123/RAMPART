# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4529_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4529_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 2778-2819 of the vulnerable file.

                $attachmentLink.prop('href'),
                $attachmentLink.prop('download')
            ];
        };

        /**
         * moves the attachment link to another element
         *
         * It is advisable to hide the attachment afterwards (AttachmentViewer.hideAttachment)
         *
         * @name   AttachmentViewer.moveAttachmentTo
         * @function
         * @param {jQuery} $element - the wrapper/container element where this should be moved to
         * @param {string} label - the text to show (%s will be replaced with the file name), will automatically be translated
         */
        me.moveAttachmentTo = function($element, label)
        {
            // move elemement to new place
            $attachmentLink.appendTo($element);

            // update text
            I18n._($attachmentLink, label, $attachmentLink.attr('download'));
        };

        /**
         * read file data as data URL using the FileReader API
         *
         * @name   AttachmentViewer.readFileData
         * @private
         * @function
         * @param {object} loadedFile (optional) loaded file object
         * @see {@link https://developer.mozilla.org/en-US/docs/Web/API/FileReader#readAsDataURL()}
         */
        function readFileData(loadedFile) {
            if (typeof FileReader === 'undefined') {
                // revert loading status…
                me.hideAttachment();
                me.hideAttachmentPreview();
                Alert.showWarning('Your browser does not support uploading encrypted files. Please use a newer browser.');
                return;
            }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2795,8 +2795,12 @@
             // move elemement to new place
             $attachmentLink.appendTo($element);
 
-            // update text
-            I18n._($attachmentLink, label, $attachmentLink.attr('download'));
+            // update text - ensuring no HTML is inserted into the text node
+            I18n._(
+                $attachmentLink,
+                $('<div />').text(label).html(),
+                $('<div />').text($attachmentLink.attr('download')).html()
+            );
         };
 
         /**
```
