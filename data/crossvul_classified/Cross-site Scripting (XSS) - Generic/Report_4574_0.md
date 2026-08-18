# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4574_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4574_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 143-184 of the vulnerable file.


  /**
   * Make file history button clickable
   */
  enableFilesHistoryBtn() {
    $('.js-from-files-history-btn').removeAttr('disabled');
  }

  /**
   * Show error message if file uploading failed
   *
   * @param {string} fileName
   * @param {integer} fileSize
   * @param {string} message
   */
  showImportFileError(fileName, fileSize, message) {
    const $alert = $('.js-import-file-error');

    const fileData = fileName + ' (' + this.humanizeSize(fileSize) + ')';

    $alert.find('.js-file-data').html(fileData);
    $alert.find('.js-error-message').html(message);
    $alert.removeClass('d-none');
  }

  /**
   * Hide file uploading error
   */
  hideImportFileError() {
    const $alert = $('.js-import-file-error');
    $alert.addClass('d-none');
  }

  /**
   * Show file size in human readable format
   *
   * @param {int} bytes
   *
   * @returns {string}
   */
  humanizeSize(bytes) {
    if (typeof bytes !== 'number') {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -160,8 +160,8 @@
 
     const fileData = fileName + ' (' + this.humanizeSize(fileSize) + ')';
 
-    $alert.find('.js-file-data').html(fileData);
-    $alert.find('.js-error-message').html(message);
+    $alert.find('.js-file-data').text(fileData);
+    $alert.find('.js-error-message').text(message);
     $alert.removeClass('d-none');
   }
 
```
