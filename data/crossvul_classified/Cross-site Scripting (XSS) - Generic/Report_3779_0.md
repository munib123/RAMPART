# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3779_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3779_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 301-341 of the vulnerable file.

                var opts = {lineNumbers: true, matchBrackets: true, indentUnit: 4, mode: "text/x-mysql"};
                CodeMirror.fromTextArea($elm[0], opts);
            } else {
                PMA_ajaxShowMessage(data.error, false);
            }
        }); // end $.get()
    }); // end $.live()

    /**
     * Attach Ajax event handlers for Drop functionality of Routines, Triggers and Events.
     */
    $('a.ajax_drop_anchor').live('click', function (event) {
        event.preventDefault();
        /**
         * @var $curr_row    Object containing reference to the current row
         */
        var $curr_row = $(this).parents('tr');
        /**
         * @var question    String containing the question to be asked for confirmation
         */
        var question = $('<div/>').text($curr_row.children('td').children('.drop_sql').html());
        // We ask for confirmation first here, before submitting the ajax request
        $(this).PMA_confirm(question, $(this).attr('href'), function (url) {
            /**
             * @var    $msg    jQuery object containing the reference to
             *                 the AJAX message shown to the user.
             */
            var $msg = PMA_ajaxShowMessage(PMA_messages['strProcessingRequest']);
            $.get(url, {'is_js_confirmed': 1, 'ajax_request': true}, function (data) {
                if (data.success === true) {
                    /**
                     * @var $table    Object containing reference to the main list of elements.
                     */
                    var $table = $curr_row.parent();
                    // Check how many rows will be left after we remove
                    // the one that the user has requested us to remove
                    if ($table.find('tr').length === 2) {
                        // If there are two rows left, it means that they are
                        // the header of the table and the rows that we are
                        // about to remove, so after the removal there will be
                        // nothing to show in the table, so we hide it.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -318,7 +318,7 @@
         /**
          * @var question    String containing the question to be asked for confirmation
          */
-        var question = $('<div/>').text($curr_row.children('td').children('.drop_sql').html());
+        var question = $('<div/>').text($curr_row.children('td').children('.drop_sql').text());
         // We ask for confirmation first here, before submitting the ajax request
         $(this).PMA_confirm(question, $(this).attr('href'), function (url) {
             /**
```
