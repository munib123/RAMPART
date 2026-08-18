# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4978_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4978_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 65-105 of the vulnerable file.

        }
    );
}
function goTo2NFStep1() {
    $.post(
        "normalization.php",
        {
            "token": PMA_commonParams.get('token'),
            "ajax_request": true,
            "db": PMA_commonParams.get('db'),
            "table": PMA_commonParams.get('table'),
            "step": '2.1'
        }, function(data) {
            $("#page_content h3").html(PMA_messages.str2NFNormalization);
            $("#mainContent legend").html(data.legendText);
            $("#mainContent h4").html(data.headText);
            $("#mainContent p").html(data.subText);
            $("#mainContent #extra").html(data.extra);
            $("#mainContent #newCols").html('');
            if (data.subText !== '') {
                $('.tblFooters').html('<input type="submit" value="' + PMA_messages.strDone + '" onclick="processDependencies(\'' + data.primary_key + '\');">');
            } else {
                if (normalizeto === '3nf') {
                    $("#mainContent #newCols").html(PMA_messages.strToNextStep);
                    setTimeout(function() {
                        goTo3NFStep1([PMA_commonParams.get('table')]);
                    }, 3000);
                }
            }
        });
}

function goToFinish1NF()
{
    if (normalizeto !== '1nf') {
        goTo2NFStep1();
        return true;
    }
    $("#mainContent legend").html(PMA_messages.strEndStep);
    $("#mainContent h4").html(
        "<h3>" + PMA_sprintf(PMA_messages.strFinishMsg, escapeHtml(PMA_commonParams.get('table'))) + "</h3>"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,7 +82,7 @@
             $("#mainContent #extra").html(data.extra);
             $("#mainContent #newCols").html('');
             if (data.subText !== '') {
-                $('.tblFooters').html('<input type="submit" value="' + PMA_messages.strDone + '" onclick="processDependencies(\'' + data.primary_key + '\');">');
+                $('.tblFooters').html('<input type="submit" value="' + PMA_messages.strDone + '" onclick="processDependencies(\'' + escapeJsString(escapeHtml(data.primary_key)) + '\');">');
             } else {
                 if (normalizeto === '3nf') {
                     $("#mainContent #newCols").html(PMA_messages.strToNextStep);
```
