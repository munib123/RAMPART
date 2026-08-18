# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4927_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4927_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 85-125 of the vulnerable file.

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
        "<h3>" + PMA_sprintf(PMA_messages.strFinishMsg, PMA_commonParams.get('table')) + "</h3>"
    );
    $("#mainContent p").html('');
    $("#mainContent #extra").html('');
    $("#mainContent #newCols").html('');
    $('.tblFooters').html('');
}

function goToStep4()
{
    $.post(
        "normalization.php",
        {
            "token": PMA_commonParams.get('token'),
            "ajax_request": true,
            "db": PMA_commonParams.get('db'),
            "table": PMA_commonParams.get('table'),
            "step4": true
        }, function(data) {
            $("#mainContent legend").html(data.legendText);
            $("#mainContent h4").html(data.headText);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -102,7 +102,7 @@
     }
     $("#mainContent legend").html(PMA_messages.strEndStep);
     $("#mainContent h4").html(
-        "<h3>" + PMA_sprintf(PMA_messages.strFinishMsg, PMA_commonParams.get('table')) + "</h3>"
+        "<h3>" + PMA_sprintf(PMA_messages.strFinishMsg, escapeHtml(PMA_commonParams.get('table'))) + "</h3>"
     );
     $("#mainContent p").html('');
     $("#mainContent #extra").html('');
```
