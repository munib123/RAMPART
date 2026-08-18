# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in javascript
**Pair ID:** 4223_3
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4223_3`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```javascript
Lines 5005-5040 of the vulnerable file.

    saveDashboardState();
    $('.edit-widget').click(function() {
        el = $(this).closest('.grid-stack-item');
        data = {
            id: el.attr('id'),
            config: JSON.parse(el.attr('config')),
            widget: el.attr('widget'),
            alias: el.attr('alias')
        }
        openGenericModalPost(baseurl + '/dashboards/getForm/edit', data);
    });
    $('.remove-widget').click(function() {
        el = $(this).closest('.grid-stack-item');
        grid.removeWidget(el);
        saveDashboardState();
    });
}

function setHomePage() {
    $.ajax({
        type: 'POST',
        url: baseurl + '/userSettings/setHomePage',
        data: {
            path: window.location.pathname
        },
        success:function (data, textStatus) {
            showMessage('success', 'Homepage set.');
            $('#setHomePage').addClass('orange');
        },
    });
}

function changeLocationFromIndexDblclick(row_index) {
    var href = $('table tr[data-row-id=\"' + row_index + '\"] .dblclickActionElement').attr('href')
    window.location = href;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5022,15 +5022,23 @@
 
 function setHomePage() {
     $.ajax({
-        type: 'POST',
+        type: 'GET',
         url: baseurl + '/userSettings/setHomePage',
-        data: {
-            path: window.location.pathname
-        },
         success:function (data, textStatus) {
-            showMessage('success', 'Homepage set.');
-            $('#setHomePage').addClass('orange');
-        },
+            $('#ajax_hidden_container').html(data);
+            var currentPage = $('#setHomePage').data('current-page');
+            $('#UserSettingPath').val(currentPage);
+            $.ajax({
+                type: 'POST',
+                url: baseurl + '/userSettings/setHomePage',
+                data: $('#UserSettingSetHomePageForm').serialize(),
+                success:function (data, textStatus) {
+                    showMessage('success', 'Homepage set.');
+                    $('#setHomePage').addClass('orange');
+                },
+            });
+
+        }
     });
 }
 
```
