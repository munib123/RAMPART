# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in javascript
**Pair ID:** 894_2
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `894_2`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```javascript
Lines 199-218 of the vulnerable file.

// ------------------------------------------------------------------
// User preferences allow/disallow UI
//

$(function () {
    $('.userprefs-allow').click(function (e) {
        if (this !== e.target) {
            return;
        }
        var el = $(this).find('input');
        if (el.prop('disabled')) {
            return;
        }
        el.prop('checked', !el.prop('checked'));
    });
});

//
// END: User preferences allow/disallow UI
// ------------------------------------------------------------------
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -216,3 +216,13 @@
 //
 // END: User preferences allow/disallow UI
 // ------------------------------------------------------------------
+
+$(function () {
+    $('.delete-server').on('click', function (e) {
+        e.preventDefault();
+        var $this = $(this);
+        $.post($this.attr('href'), $this.attr('data-post'), function () {
+            window.location.replace('index.php');
+        });
+    });
+});
```
