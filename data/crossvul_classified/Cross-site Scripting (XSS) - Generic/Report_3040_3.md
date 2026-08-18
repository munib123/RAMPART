# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 3040_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3040_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 32-72 of the vulnerable file.


    </body>

    <!--
    <script type='text/javascript'
        src='http://getfirebug.com/releases/lite/1.2/firebug-lite-compressed.js'></script>
    -->

    <script type="text/javascript">
        var INCLUDE_URI= "../";
    </script>
    <script src="../core/util.js"></script>
    <script src="../app/webutil.js"></script>

    <script>
        var fname, start_time;

        function message(str) {
            console.log(str);
            var cell = document.getElementById('messages');
            cell.innerHTML += str + "\n";
            cell.scrollTop = cell.scrollHeight;
        }

        fname = WebUtil.getQueryVar('data', null);
        if (fname) {
            message("Loading " + fname);
            // Load supporting scripts
            WebUtil.load_scripts({
                'core': ["base64.js", "websock.js", "des.js", "input/keysym.js",
                         "input/keysymdef.js", "input/xtscancodes.js", "input/util.js",
                         "input/devices.js", "display.js", "rfb.js", "inflator.js"],
                'tests': ["playback.js"],
                'recordings': [fname]});

        } else {
            message("Must specify data=FOO in query string.");
        }

        disconnected = function (rfb, reason) {
            if (reason) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,7 +49,7 @@
         function message(str) {
             console.log(str);
             var cell = document.getElementById('messages');
-            cell.innerHTML += str + "\n";
+            cell.textContent += str + "\n";
             cell.scrollTop = cell.scrollHeight;
         }
 
@@ -76,7 +76,7 @@
         }
 
         notification = function (rfb, mesg, level, options) {
-            document.getElementById('VNC_status').innerHTML = mesg;
+            document.getElementById('VNC_status').textContent = mesg;
         }
 
         function start() {
```
