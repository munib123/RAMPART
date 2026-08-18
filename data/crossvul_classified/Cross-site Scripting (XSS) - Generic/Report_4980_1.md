# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4980_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4980_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 621-661 of the vulnerable file.

                    PMA_ajaxShowMessage(data.error, false);
                }
            }
        );
    });
    $("#extra").on("click", "#moveRepeatingGroup", function() {
        var repeatingCols = '';
        $("#extra input[type=checkbox]:checked").each(function() {
            repeatingCols += $(this).val() + ', ';
        });

        if (repeatingCols !== '') {
            var newColName = $("#extra input[type=checkbox]:checked:first").val();
            repeatingCols = repeatingCols.slice(0, -2);
            var confirmStr = PMA_sprintf(PMA_messages.strMoveRepeatingGroup, escapeHtml(repeatingCols), escapeHtml(PMA_commonParams.get('table')));
            confirmStr += '<input type="text" name="repeatGroupTable" placeholder="' + PMA_messages.strNewTablePlaceholder + '"/>' +
                '( ' + escapeHtml(primary_key.toString()) + ', <input type="text" name="repeatGroupColumn" placeholder="' + PMA_messages.strNewColumnPlaceholder + '" value="' + escapeHtml(newColName) + '">)' +
                '</ol>';
            $("#newCols").html(confirmStr);
            $('.tblFooters').html('<input type="submit" value="' + PMA_messages.strCancel + '" onclick="$(\'#newCols\').html(\'\');$(\'#extra input[type=checkbox]\').removeAttr(\'checked\')"/>' +
                '<input type="submit" value="' + PMA_messages.strGo + '" onclick="moveRepeatingGroup(\'' + repeatingCols + '\')"/>');
        }
    });
    $("#mainContent p").on("click", "#createPrimaryKey", function(event) {
        event.preventDefault();
        var url = { create_index: 1,
            server:  PMA_commonParams.get('server'),
            db: PMA_commonParams.get('db'),
            table: PMA_commonParams.get('table'),
            token: PMA_commonParams.get('token'),
            added_fields: 1,
            add_fields:1,
            index: {Key_name:'PRIMARY'},
            ajax_request: true
        };
        var title = PMA_messages.strAddPrimaryKey;
        indexEditorDialog(url, title, function(){
            //on success
            $(".sqlqueryresults").remove();
            $('.result_query').remove();
            $('.tblFooters').html('');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -638,7 +638,7 @@
                 '</ol>';
             $("#newCols").html(confirmStr);
             $('.tblFooters').html('<input type="submit" value="' + PMA_messages.strCancel + '" onclick="$(\'#newCols\').html(\'\');$(\'#extra input[type=checkbox]\').removeAttr(\'checked\')"/>' +
-                '<input type="submit" value="' + PMA_messages.strGo + '" onclick="moveRepeatingGroup(\'' + repeatingCols + '\')"/>');
+                '<input type="submit" value="' + PMA_messages.strGo + '" onclick="moveRepeatingGroup(\'' + escapeJsString(escapeHtml(repeatingCols)) + '\')"/>');
         }
     });
     $("#mainContent p").on("click", "#createPrimaryKey", function(event) {
```
