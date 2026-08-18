# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3782_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3782_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 115-155 of the vulnerable file.

            add = 0;
        }
    }
    // Parse version
    var x = str.split('.');
    // Use 0 for non existing parts
    var maj = parseInt(x[0]) || 0;
    var min = parseInt(x[1]) || 0;
    var pat = parseInt(x[2]) || 0;
    var hotfix = parseInt(x[3]) || 0;
    return  maj * 100000000 + min * 1000000 + pat * 10000 + hotfix * 100 + add;
}

/**
 * Indicates current available version on main page.
 */
function PMA_current_version(data)
{
    var current = parseVersionString(pmaversion);
    var latest = parseVersionString(data['version']);
    var version_information_message = PMA_messages['strLatestAvailable'] + ' ' + data['version'];
    if (latest > current) {
        var message = $.sprintf(PMA_messages['strNewerVersion'], data['version'], data['date']);
        if (Math.floor(latest / 10000) == Math.floor(current / 10000)) {
            /* Security update */
            klass = 'error';
        } else {
            klass = 'notice';
        }
        $('#maincontainer').after('<div class="' + klass + '">' + message + '</div>');
    }
    if (latest == current) {
        version_information_message = ' (' + PMA_messages['strUpToDate'] + ')';
    }
    $('#li_pma_version').append(version_information_message);
}

/**
 * for libraries/display_change_password.lib.php
 *     libraries/user_password.php
 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -132,9 +132,9 @@
 {
     var current = parseVersionString(pmaversion);
     var latest = parseVersionString(data['version']);
-    var version_information_message = PMA_messages['strLatestAvailable'] + ' ' + data['version'];
+    var version_information_message = PMA_messages['strLatestAvailable'] + ' ' + escapeHtml(data['version']);
     if (latest > current) {
-        var message = $.sprintf(PMA_messages['strNewerVersion'], data['version'], data['date']);
+        var message = $.sprintf(PMA_messages['strNewerVersion'], escapeHtml(data['version']), escapeHtml(data['date']));
         if (Math.floor(latest / 10000) == Math.floor(current / 10000)) {
             /* Security update */
             klass = 'error';
```
