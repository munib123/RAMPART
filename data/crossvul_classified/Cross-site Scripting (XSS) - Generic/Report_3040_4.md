# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 3040_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3040_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 94-134 of the vulnerable file.

                var innerH = window.innerHeight;
                var controlbarH = document.getElementById('noVNC_status_bar').offsetHeight;
                if (innerW !== undefined && innerH !== undefined)
                    rfb.requestDesktopSize(innerW, innerH - controlbarH);
            }
        }
        function FBUComplete(rfb, fbu) {
            UIresize();
            rfb.set_onFBUComplete(function() { });
        }
        function updateDesktopName(rfb, name) {
            desktopName = name;
        }
        function passwordRequired(rfb, msg) {
            if (typeof msg === 'undefined') {
                msg = 'Password Required: ';
            }
            var html;
            html = '<form onsubmit="return setPassword();"';
            html += '  style="margin-bottom: 0px">';
            html += msg;
            html += '<input type=password size=10 id="password_input" class="noVNC_status">';
            html += '<\/form>';
            status(html, "warn");
        }
        function setPassword() {
            rfb.sendPassword(document.getElementById('password_input').value);
            return false;
        }
        function sendCtrlAltDel() {
            rfb.sendCtrlAltDel();
            return false;
        }
        function xvpShutdown() {
            rfb.xvpShutdown();
            return false;
        }
        function xvpReboot() {
            rfb.xvpReboot();
            return false;
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -111,10 +111,14 @@
             var html;
             html = '<form onsubmit="return setPassword();"';
             html += '  style="margin-bottom: 0px">';
-            html += msg;
+            html += '<label></label>'
             html += '<input type=password size=10 id="password_input" class="noVNC_status">';
             html += '<\/form>';
-            status(html, "warn");
+
+            // bypass status() because it sets text content
+            document.getElementById('noVNC_status_bar').setAttribute("class", "noVNC_status_warn");
+            document.getElementById('noVNC_status').innerHTML = html;
+            document.getElementById('noVNC_status').querySelector('label').textContent = msg;
         }
         function setPassword() {
             rfb.sendPassword(document.getElementById('password_input').value);
@@ -146,7 +150,7 @@
                     level = "warn";
             }
             document.getElementById('noVNC_status_bar').setAttribute("class", "noVNC_status_" + level);
-            document.getElementById('noVNC_status').innerHTML = text;
+            document.getElementById('noVNC_status').textContent = text;
         }
         function updateState(rfb, state, oldstate) {
             var cad = document.getElementById('sendCtrlAltDelButton');
```
