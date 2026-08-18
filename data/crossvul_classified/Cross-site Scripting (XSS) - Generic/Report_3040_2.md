# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 3040_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3040_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 48-88 of the vulnerable file.


            // Load supporting scripts
            WebUtil.load_scripts({
                'core': ["base64.js", "websock.js", "des.js", "input/keysym.js",
                         "input/keysymdef.js", "input/xtscancodes.js", "input/util.js",
                         "input/devices.js", "display.js", "rfb.js", "inflator.js"],
                'tests': ["playback.js"],
                'recordings': [fname]});
        } else {
            msg("Must specifiy data=FOO.js in query string.");
        }

        var start_time, VNC_frame_data, pass, passes, encIdx,
            encOrder = ['raw', 'rre', 'hextile', 'tightpng', 'copyrect'],
            encTot = {}, encMin = {}, encMax = {},
            passCur, passTot, passMin, passMax;

        function msg(str) {
            console.log(str);
            var cell = document.getElementById('messages');
            cell.innerHTML += str + "\n";
            cell.scrollTop = cell.scrollHeight;
        }
        function dbgmsg(str) {
            if (Util.get_logging() === 'debug') {
                msg(str);
            }
        }

        disconnected = function (rfb, reason) {
            if (reason) {
                msg("noVNC sent '" + state +
                    "' state during pass " + pass +
                    ", iteration " + iteration +
                    " frame " + frame_idx);
                test_state = 'failed';
            }
        }

        notification = function (rfb, mesg, level, options) {
            document.getElementById('VNC_status').innerHTML = mesg;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,7 +65,7 @@
         function msg(str) {
             console.log(str);
             var cell = document.getElementById('messages');
-            cell.innerHTML += str + "\n";
+            cell.textContent += str + "\n";
             cell.scrollTop = cell.scrollHeight;
         }
         function dbgmsg(str) {
@@ -85,7 +85,7 @@
         }
 
         notification = function (rfb, mesg, level, options) {
-            document.getElementById('VNC_status').innerHTML = mesg;
+            document.getElementById('VNC_status').textContent = mesg;
         }
 
         function do_test() {
```
