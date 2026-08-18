# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2268_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2268_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 766-808 of the vulnerable file.

         * Setting hash leads to reload in webkit:
         * http://www.quirksmode.org/bugreports/archives/2005/05/Safari_13_visual_anomaly_with_windowlocationhref.html
         *
         * so we expect that users are not running an ancient Safari version
         */

        userChange = false;
        if (ready) {
            window.location.hash = "PMAURL-" + index + ":" + hash;
            resetFavicon();
        } else {
            savedHash = "PMAURL-" + index + ":" + hash;
        }
    }
    /**
     * Start initialisation
     */
    if (window.location.hash.substring(0, 8) == '#PMAURL-') {
        // We have a valid hash, let's redirect the user
        // to the page that it's pointing to
        window.location = window.location.hash.substring(
            window.location.hash.indexOf(':') + 1
        );
    } else {
        // We don't have a valid hash, so we'll set it up
        // when the page finishes loading
        jQuery(function () {
            /* Check if we should set URL */
            if (savedHash !== "") {
                window.location.hash = savedHash;
                savedHash = "";
                resetFavicon();
            }
            // Indicate that we're done initialising
            ready = true;
        });
    }
    /**
     * Register an event handler for when the url hash changes
     */
    jQuery(function () {
        jQuery(window).hashchange(function () {
            if (userChange === false) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -783,9 +783,16 @@
     if (window.location.hash.substring(0, 8) == '#PMAURL-') {
         // We have a valid hash, let's redirect the user
         // to the page that it's pointing to
-        window.location = window.location.hash.substring(
-            window.location.hash.indexOf(':') + 1
-        );
+        var colon_position = window.location.hash.indexOf(':');
+        var questionmark_position = window.location.hash.indexOf('?');
+        if (colon_position != -1 && questionmark_position != -1 && colon_position < questionmark_position) {
+            var hash_url = window.location.hash.substring(colon_position + 1, questionmark_position);
+            if (PMA_gotoWhitelist.indexOf(hash_url) != -1) {
+                window.location = window.location.hash.substring(
+                    colon_position + 1
+                );
+            }
+        }
     } else {
         // We don't have a valid hash, so we'll set it up
         // when the page finishes loading
```
