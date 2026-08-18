# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3781_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3781_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 111-151 of the vulnerable file.

        } else if (state[1].substr(0, 5) == 'alpha') {
            add =  - 60 - parseInt(state[1].substr(5));
        } else if (state[1].substr(0, 3) == 'dev') {
            /* We don't handle dev, it's git snapshot */
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
function PMA_current_version()
{
    var current = parseVersionString(pmaversion);
    var latest = parseVersionString(PMA_latest_version);
    var version_information_message = PMA_messages['strLatestAvailable'] + ' ' + PMA_latest_version;
    if (latest > current) {
        var message = $.sprintf(PMA_messages['strNewerVersion'], PMA_latest_version, PMA_latest_date);
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

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -128,13 +128,13 @@
 /**
  * Indicates current available version on main page.
  */
-function PMA_current_version()
+function PMA_current_version(data)
 {
     var current = parseVersionString(pmaversion);
-    var latest = parseVersionString(PMA_latest_version);
-    var version_information_message = PMA_messages['strLatestAvailable'] + ' ' + PMA_latest_version;
+    var latest = parseVersionString(data['version']);
+    var version_information_message = PMA_messages['strLatestAvailable'] + ' ' + data['version'];
     if (latest > current) {
-        var message = $.sprintf(PMA_messages['strNewerVersion'], PMA_latest_version, PMA_latest_date);
+        var message = $.sprintf(PMA_messages['strNewerVersion'], data['version'], data['date']);
         if (Math.floor(latest / 10000) == Math.floor(current / 10000)) {
             /* Security update */
             klass = 'error';
@@ -1734,7 +1734,7 @@
             seriesDefaults: {
                 renderer: $.jqplot.PieRenderer,
                 rendererOptions: {
-                    showDataLabels:  true 
+                    showDataLabels:  true
                 }
             },
             legend: {
@@ -3218,7 +3218,7 @@
      * Load version information asynchronously.
      */
     if ($('.jsversioncheck').length > 0) {
-        $.getScript('http://www.phpmyadmin.net/home_page/version.js', PMA_current_version);
+        $.getJSON('http://www.phpmyadmin.net/home_page/version.json', {}, PMA_current_version);
     }
 
     /**
```
