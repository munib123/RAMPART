# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 3040_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3040_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 28-68 of the vulnerable file.

    <script src="../core/base64.js"></script>
    <script src="../core/input/keysym.js"></script>
    <script src="../core/input/keysymdef.js"></script> 
    <script src="../core/input/xtscancodes.js"></script>
    <script src="../core/input/util.js"></script>
    <script src="../core/input/devices.js"></script>
    <script src="../core/display.js"></script>
    <script>
        var msg_cnt = 0, iterations,
            width = 400, height = 200,
            canvas, keyboard, mouse;

        var newline = "\n";
        if (Util.Engine.trident) {
            var newline = "<br>\n";
        }

        function message(str) {
            console.log(str);
            cell = document.getElementById('messages');
            cell.innerHTML += msg_cnt + ": " + str + newline;
            cell.scrollTop = cell.scrollHeight;
            msg_cnt++;
        }

        function mouseButton(x, y, down, bmask) {
            msg = 'mouse x,y: ' + x + ',' + y + '  down: ' + down;
            msg += ' bmask: ' + bmask;
            message(msg);
        }

        function mouseMove(x, y) {
            msg = 'mouse x,y: ' + x + ',' + y;
            //console.log(msg);
        }

        function rfbKeyPress(keysym, down) {
            var d = down ? "down" : " up ";
            var key = keysyms.lookup(keysym);
            var msg = "RFB keypress " + d + " keysym: " + keysym;
            if (key && key.keyname) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,7 +45,7 @@
         function message(str) {
             console.log(str);
             cell = document.getElementById('messages');
-            cell.innerHTML += msg_cnt + ": " + str + newline;
+            cell.textContent += msg_cnt + ": " + str + newline;
             cell.scrollTop = cell.scrollHeight;
             msg_cnt++;
         }
```
