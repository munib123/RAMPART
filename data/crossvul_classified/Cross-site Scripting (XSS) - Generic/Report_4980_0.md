# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4980_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4980_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 221-261 of the vulnerable file.

        show: false,
        hide: false
    };

    $elements.tooltip($.extend(true, defaultOptions, additionalOptions));
}

/**
 * HTML escaping
 */

function escapeHtml(unsafe) {
    if (typeof(unsafe) != 'undefined') {
        return unsafe
            .toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    } else {
        return false;
    }
}

function PMA_sprintf() {
    return sprintf.apply(this, arguments);
}

/**
 * Hides/shows the default value input field, depending on the default type
 * Ticks the NULL checkbox if NULL is chosen as default value.
 */
function PMA_hideShowDefaultValue($default_type)
{
    if ($default_type.val() == 'USER_DEFINED') {
        $default_type.siblings('.default_value').show().focus();
    } else {
        $default_type.siblings('.default_value').hide();
        if ($default_type.val() == 'NULL') {
            var $null_checkbox = $default_type.closest('tr').find('.allow_null');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -238,6 +238,24 @@
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
+    } else {
+        return false;
+    }
+}
+
+function escapeJsString(unsafe) {
+    if (typeof(unsafe) != 'undefined') {
+        return unsafe
+            .toString()
+            .replace("\000", '')
+            .replace('\\', '\\\\')
+            .replace('\'', '\\\'')
+            .replace("&#039;", "\\\&#039;")
+            .replace('"', '\"')
+            .replace("&quot;", "\&quot;")
+            .replace("\n", '\n')
+            .replace("\r", '\r')
+            .replace(/<\/script/gi, '</\' + \'script')
     } else {
         return false;
     }
```
