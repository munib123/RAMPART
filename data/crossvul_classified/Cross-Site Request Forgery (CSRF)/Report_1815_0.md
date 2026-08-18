# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in javascript
**Pair ID:** 1815_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1815_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```javascript
Lines 340-360 of the vulnerable file.



    //defaults that need to be set on ready
    $(document).ready(function () {

        //adds a default ignore parameter to jquery validation
        if ($.validator) {
            $.validator.setDefaults({ ignore: ".ignore" });
        }

        //adds a "re-parse" method to the Unobtrusive JS framework since Parse doesn't actually reparse
        if ($.validator && $.validator.unobtrusive) {
            $.validator.unobtrusive.reParse = function ($selector) {
                $selector.removeData("validator");
                $.validator.unobtrusive.parse($selector);
            };
        }

    });

})(jQuery);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -357,4 +357,20 @@
 
     });
 
+    //This sets the default jquery ajax headers to include our csrf token, we
+    // need to user the beforeSend method because our token changes per user/login so
+    // it cannot be static
+    $.ajaxSetup({
+        beforeSend: function (xhr) {
+
+            function getCookie(name) {
+                var value = "; " + document.cookie;
+                var parts = value.split("; " + name + "=");
+                if (parts.length === 2) return parts.pop().split(";").shift();
+            }
+
+            xhr.setRequestHeader("X-XSRF-TOKEN", getCookie("XSRF-TOKEN"));
+        }
+    });
+
 })(jQuery);
```
