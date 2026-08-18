# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2236_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2236_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 181-221 of the vulnerable file.

        });
    });

    /**
     * Attach Event Handler for 'Drop Column'
     */
    $("a.drop_column_anchor.ajax").live('click', function (event) {
        event.preventDefault();
        /**
         * @var curr_table_name String containing the name of the current table
         */
        var curr_table_name = $(this).closest('form').find('input[name=table]').val();
        /**
         * @var curr_row    Object reference to the currently selected row (i.e. field in the table)
         */
        var $curr_row = $(this).parents('tr');
        /**
         * @var curr_column_name    String containing name of the field referred to by {@link curr_row}
         */
        var curr_column_name = $curr_row.children('th').children('label').text();
        /**
         * @var $after_field_item    Corresponding entry in the 'After' field.
         */
        var $after_field_item = $("select[name='after_field'] option[value='" + curr_column_name + "']");
        /**
         * @var question    String containing the question to be asked for confirmation
         */
        var question = $.sprintf(PMA_messages.strDoYouReally, 'ALTER TABLE `' + escapeHtml(curr_table_name) + '` DROP `' + escapeHtml(curr_column_name) + '`;');
        $(this).PMA_confirm(question, $(this).attr('href'), function (url) {
            var $msg = PMA_ajaxShowMessage(PMA_messages.strDroppingColumn, false);
            $.get(url, {'is_js_confirmed' : 1, 'ajax_request' : true, 'ajax_page_request' : true}, function (data) {
                if (data.success === true) {
                    PMA_ajaxRemoveMessage($msg);
                    if ($('#result_query').length) {
                        $('#result_query').remove();
                    }
                    if (data.sql_query) {
                        $('<div id="result_query"></div>')
                            .html(data.sql_query)
                            .prependTo('#page_content');
                        PMA_highlightSQL($('#page_content'));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -198,6 +198,7 @@
          * @var curr_column_name    String containing name of the field referred to by {@link curr_row}
          */
         var curr_column_name = $curr_row.children('th').children('label').text();
+        curr_column_name = escapeHtml(curr_column_name);
         /**
          * @var $after_field_item    Corresponding entry in the 'After' field.
          */
```
