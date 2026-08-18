# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 5139_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5139_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 3517-3557 of the vulnerable file.

                escapeHtml(central_column_list[db + '_' + table][i].col_name) +
                '</span><br><span style="color:gray">' + central_column_list[db + '_' + table][i].col_type;

            if (central_column_list[db + '_' + table][i].col_attribute !== '') {
                fields += '(' + escapeHtml(central_column_list[db + '_' + table][i].col_attribute) + ') ';
            }
            if (central_column_list[db + '_' + table][i].col_length !== '') {
                fields += '(' + escapeHtml(central_column_list[db + '_' + table][i].col_length) +') ';
            }
            fields += escapeHtml(central_column_list[db + '_' + table][i].col_extra) + '</span>' +
                '</div></td>';
            if (pick) {
                fields += '<td><input class="pick" style="width:100%" type="submit" value="' +
                    PMA_messages.pickColumn + '" onclick="autoPopulate(\'' + colid + '\',' + i + ')"/></td>';
            }
            fields += '</tr>';
        }
        var result_pointer = i;
        var search_in = '<input type="text" class="filter_rows" placeholder="' + PMA_messages.searchList + '">';
        if (fields === '') {
            fields = PMA_sprintf(PMA_messages.strEmptyCentralList, "'" + db + "'");
            search_in = '';
        }
        var seeMore = '';
        if (list_size > maxRows) {
            seeMore = "<fieldset class='tblFooters' style='text-align:center;font-weight:bold'>" +
                "<a href='#' id='seeMore'>" + PMA_messages.seeMore + "</a></fieldset>";
        }
        var central_columns_dialog = "<div style='max-height:400px'>" +
            "<fieldset>" +
            search_in +
            "<table id='col_list' style='width:100%' class='values'>" + fields + "</table>" +
            "</fieldset>" +
            seeMore +
            "</div>";

        var width = parseInt(
            (parseInt($('html').css('font-size'), 10) / 13) * 500,
            10
        );
        if (! width) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3534,7 +3534,7 @@
         var result_pointer = i;
         var search_in = '<input type="text" class="filter_rows" placeholder="' + PMA_messages.searchList + '">';
         if (fields === '') {
-            fields = PMA_sprintf(PMA_messages.strEmptyCentralList, "'" + db + "'");
+            fields = PMA_sprintf(PMA_messages.strEmptyCentralList, "'" + escapeHtml(db) + "'");
             search_in = '';
         }
         var seeMore = '';
```
