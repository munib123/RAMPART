# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4975_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4975_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 111-151 of the vulnerable file.

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
            $("#mainContent p").html(data.subText);
            $("#mainContent #extra").html(data.extra);
            $("#mainContent #newCols").html('');
            $('.tblFooters').html('');
            for(var pk in primary_key) {
                $("#extra input[value='" + primary_key[pk] + "']").attr("disabled","disabled");
            }
        }
    );
}

function goToStep3()
{
    $.post(
        "normalization.php",
        {
            "token": PMA_commonParams.get('token'),
            "ajax_request": true,
            "db": PMA_commonParams.get('db'),
            "table": PMA_commonParams.get('table'),
            "step3": true
        }, function(data) {
            $("#mainContent legend").html(data.legendText);
            $("#mainContent h4").html(data.headText);
            $("#mainContent p").html(data.subText);
            $("#mainContent #extra").html(data.extra);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -128,7 +128,7 @@
             $("#mainContent #newCols").html('');
             $('.tblFooters').html('');
             for(var pk in primary_key) {
-                $("#extra input[value='" + primary_key[pk] + "']").attr("disabled","disabled");
+                $("#extra input[value='" + escapeJsString(primary_key[pk]) + "']").attr("disabled","disabled");
             }
         }
     );
@@ -153,7 +153,7 @@
             $('.tblFooters').html('');
             primary_key = $.parseJSON(data.primary_key);
             for(var pk in primary_key) {
-                $("#extra input[value='" + primary_key[pk] + "']").attr("disabled","disabled");
+                $("#extra input[value='" + escapeJsString(primary_key[pk]) + "']").attr("disabled","disabled");
             }
         }
     );
```
