# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 1195_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1195_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 344-384 of the vulnerable file.

              <a id="titlecross" onClick="chat.hide();return false;">-&nbsp;</a>
              <a id="titlesticky" onClick="chat.stickToScreen(true);$('#options-stickychat').prop('checked', true);return false;" data-l10n-id="pad.chat.stick.title">█&nbsp;&nbsp;</a>
            </div>
            <div id="chattext" class="authorColors" aria-live="polite" aria-relevant="additions removals text" role="log" aria-atomic="false">
                <div alt="loading.." id="chatloadmessagesball" class="chatloadmessages loadingAnimation" align="top"></div>
                <button id="chatloadmessagesbutton" class="chatloadmessages" data-l10n-id="pad.chat.loadmessages"></button>
            </div>
            <div id="chatinputbox">
                <form>
                    <input id="chatinput" type="text" maxlength="999" data-l10n-id="pad.chat.writeMessage.placeholder">
                </form>
            </div>
        </div>

        <div id="focusprotector">&nbsp;</div>

        <% e.end_block(); %>

        <% e.begin_block("scripts"); %>
        <script type="text/javascript">
            // @license magnet:?xt=urn:btih:8e4f440f4c65981c5bf93c76d35135ba5064d8b7&dn=apache-2.0.txt
            (function() {
              // Display errors on page load to the user
              // (Gets overridden by padutils.setupGlobalExceptionHandler)
              var originalHandler = window.onerror;
              window.onerror = function(msg, url, line) {
                var box   = document.getElementById('editorloadingbox');
                box.innerHTML = '<p><b>An error occurred while loading the pad</b></p>'
                              + '<p><b>'+msg+'</b> '
                              + '<small>in '+ url +' (line '+ line +')</small></p>';
                // call original error handler
                if(typeof(originalHandler) == 'function') originalHandler.call(null, arguments);
              };
            })();
            // @license-end
        </script>

        <script type="text/javascript" src="../static/js/require-kernel.js"></script>
        <script type="text/javascript" src="../socket.io/socket.io.js"></script>

        <!-- Include base packages manually (this help with debugging) -->
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -361,6 +361,8 @@
 
         <% e.begin_block("scripts"); %>
         <script type="text/javascript">
+            var padutils = require('../static/js/pad_utils').padutils;
+
             // @license magnet:?xt=urn:btih:8e4f440f4c65981c5bf93c76d35135ba5064d8b7&dn=apache-2.0.txt
             (function() {
               // Display errors on page load to the user
@@ -370,7 +372,7 @@
                 var box   = document.getElementById('editorloadingbox');
                 box.innerHTML = '<p><b>An error occurred while loading the pad</b></p>'
                               + '<p><b>'+msg+'</b> '
-                              + '<small>in '+ url +' (line '+ line +')</small></p>';
+                              + '<small>in '+ padutils.escapeHTML(url) +' (line '+ line +')</small></p>';
                 // call original error handler
                 if(typeof(originalHandler) == 'function') originalHandler.call(null, arguments);
               };
```
