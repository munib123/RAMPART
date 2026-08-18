# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2236_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2236_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 3531-3571 of the vulnerable file.

/**
 * Unbind all event handlers before tearing down a page
 */
AJAX.registerTeardown('functions.js', function () {
    $("#drop_tbl_anchor.ajax").die('click');
    $("#drop_view_anchor.ajax").die('click');
    $("#truncate_tbl_anchor.ajax").die('click');
});
/**
 * Attach Ajax event handlers for Drop Table.
 */
AJAX.registerOnload('functions.js', function () {
    $("#drop_tbl_anchor.ajax").live('click', function (event) {
        event.preventDefault();
        /**
         * @var question    String containing the question to be asked for confirmation
         */
        var question = PMA_messages.strDropTableStrongWarning + ' ';
        question += $.sprintf(
            PMA_messages.strDoYouReally,
            'DROP TABLE ' + PMA_commonParams.get('table')
        );

        $(this).PMA_confirm(question, $(this).attr('href'), function (url) {

            var $msgbox = PMA_ajaxShowMessage(PMA_messages.strProcessingRequest);
            $.get(url, {'is_js_confirmed': '1', 'ajax_request': true}, function (data) {
                if (data.success === true) {
                    PMA_ajaxRemoveMessage($msgbox);
                    // Table deleted successfully, refresh both the frames
                    PMA_reloadNavigation();
                    PMA_commonParams.set('table', '');
                    PMA_commonActions.refreshMain(
                        PMA_commonParams.get('opendb_url'),
                        function () {
                            PMA_ajaxShowMessage(data.message);
                        }
                    );
                } else {
                    PMA_ajaxShowMessage(data.error, false);
                }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3548,7 +3548,7 @@
         var question = PMA_messages.strDropTableStrongWarning + ' ';
         question += $.sprintf(
             PMA_messages.strDoYouReally,
-            'DROP TABLE ' + PMA_commonParams.get('table')
+            'DROP TABLE ' + escapeHtml(PMA_commonParams.get('table'))
         );
 
         $(this).PMA_confirm(question, $(this).attr('href'), function (url) {
@@ -3614,7 +3614,7 @@
         var question = PMA_messages.strTruncateTableStrongWarning + ' ';
         question += $.sprintf(
             PMA_messages.strDoYouReally,
-            'TRUNCATE ' + PMA_commonParams.get('table')
+            'TRUNCATE ' + escapeHtml(PMA_commonParams.get('table'))
         );
         $(this).PMA_confirm(question, $(this).attr('href'), function (url) {
             PMA_ajaxShowMessage(PMA_messages.strProcessingRequest);
```
