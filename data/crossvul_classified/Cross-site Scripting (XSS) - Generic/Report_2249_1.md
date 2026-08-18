# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2249_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2249_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 102-142 of the vulnerable file.

/**
 * @description <p>Ajax scripts for sql and browse pages</p>
 *
 * Actions ajaxified here:
 * <ul>
 * <li>Retrieve results of an SQL query</li>
 * <li>Paginate the results table</li>
 * <li>Sort the results table</li>
 * <li>Change table according to display options</li>
 * <li>Grid editing of data</li>
 * <li>Saving a bookmark</li>
 * </ul>
 *
 * @name        document.ready
 * @memberOf    jQuery
 */
AJAX.registerOnload('sql.js', function () {
    // Delete row from SQL results
    $('a.delete_row.ajax').live('click', function (e) {
        e.preventDefault();
        var question = $.sprintf(PMA_messages.strDoYouReally, $(this).closest('td').find('div').text());
        var $link = $(this);
        $link.PMA_confirm(question, $link.attr('href'), function (url) {
            $msgbox = PMA_ajaxShowMessage();
            $.get(url, {'ajax_request': true, 'is_js_confirmed': true}, function (data) {
                if (data.success) {
                    PMA_ajaxShowMessage(data.message);
                    $link.closest('tr').remove();
                } else {
                    PMA_ajaxShowMessage(data.error, false);
                }
            });
        });
    });

    // Ajaxification for 'Bookmark this SQL query'
    $('#bookmarkQueryForm').live('submit', function (e) {
        e.preventDefault();
        PMA_ajaxShowMessage();
        $.post($(this).attr('action'), 'ajax_request=1&' + $(this).serialize(), function (data) {
            if (data.success) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -119,7 +119,7 @@
     // Delete row from SQL results
     $('a.delete_row.ajax').live('click', function (e) {
         e.preventDefault();
-        var question = $.sprintf(PMA_messages.strDoYouReally, $(this).closest('td').find('div').text());
+        var question = $.sprintf(PMA_messages.strDoYouReally, escapeHtml($(this).closest('td').find('div').text()));
         var $link = $(this);
         $link.PMA_confirm(question, $link.attr('href'), function (url) {
             $msgbox = PMA_ajaxShowMessage();
```
