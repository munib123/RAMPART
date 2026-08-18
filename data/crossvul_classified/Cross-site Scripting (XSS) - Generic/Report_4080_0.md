# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4080_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4080_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1322-1362 of the vulnerable file.

        timeout: 0,
        dictRemoveFile: translate_javascripts['Delete'],
        dictFileTooBig: translate_javascripts['ToLargeFile'],
        dictCancelUpload: translate_javascripts['Delete'],
        sending: function(file, response) {
          checkDropzoneMode();
          expanderElem.addClass('expand').click();
          errorElem.html('');
        },
        queuecomplete: function() {
          checkDropzoneMode();
          dropZoneElem.sortable('enable');
          imagesProduct.updateExpander();
        },
        processing: function() {
          dropZoneElem.sortable('disable');
        },
        success: function(file, response) {
          //manage error on uploaded file
          if (response.error !== 0) {
            errorElem.append('<p>' + file.name + ': ' + response.error + '</p>');
            this.removeFile(file);
            return;
          }

          //define id image to file preview
          $(file.previewElement).attr('data-id', response.id);
          $(file.previewElement).attr('url-update', response.url_update);
          $(file.previewElement).attr('url-delete', response.url_delete);
          $(file.previewElement).addClass('ui-sortable-handle');
          if (response.cover === 1) {
            imagesProduct.updateDisplayCover(response.id);
          }
        },
        error: function(file, response) {
          var message = '';
          if ($.type(response) === 'undefined') {
            return;
          } else if ($.type(response) === 'string') {
            message = response;
          } else if (response.message) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1339,7 +1339,7 @@
         success: function(file, response) {
           //manage error on uploaded file
           if (response.error !== 0) {
-            errorElem.append('<p>' + file.name + ': ' + response.error + '</p>');
+            errorElem.append($('<p></p>').text(file.name + ': ' + response.error));
             this.removeFile(file);
             return;
           }
@@ -1368,7 +1368,7 @@
           }
 
           //append new error
-          errorElem.append('<p>' + file.name + ': ' + message + '</p>');
+          errorElem.append($('<p></p>').text(file.name + ': ' + message));
 
           //remove uploaded item
           this.removeFile(file);
```
