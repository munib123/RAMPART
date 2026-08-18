# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3040_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3040_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 31-71 of the vulnerable file.

            var msg = "";

            msg += "<div>";
            msg += event.message;
            msg += "</div>";

            msg += " <div class=\"noVNC_location\">";
            msg += event.filename;
            msg += ":" + event.lineno + ":" + event.colno;
            msg += "</div>";

            if ((event.error !== undefined) &&
                (event.error.stack !== undefined)) {
                msg += "<div class=\"noVNC_stack\">";
                msg += event.error.stack;
                msg += "</div>";
            }

            document.getElementById('noVNC_fallback_error')
                .classList.add("noVNC_open");
            document.getElementById('noVNC_fallback_errormsg').innerHTML = msg;
        } catch (exc) {
            document.write("noVNC encountered an error.");
        }
        // Don't return true since this would prevent the error
        // from being printed to the browser console.
        return false;
    });

    // Set up translations
    var LINGUAS = ["de", "el", "nl", "sv"];
    Util.Localisation.setup(LINGUAS);
    if (Util.Localisation.language !== "en") {
        WebUtil.load_scripts(
            {'app': ["locale/" + Util.Localisation.language + ".js"]});
    }

    /* [begin skip-as-module] */
    // Load supporting scripts
    WebUtil.load_scripts(
        {'core': ["base64.js", "websock.js", "des.js", "input/keysymdef.js",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,7 +48,7 @@
 
             document.getElementById('noVNC_fallback_error')
                 .classList.add("noVNC_open");
-            document.getElementById('noVNC_fallback_errormsg').innerHTML = msg;
+            document.getElementById('noVNC_fallback_errormsg').textContent = msg;
         } catch (exc) {
             document.write("noVNC encountered an error.");
         }
@@ -416,7 +416,7 @@
 
             switch (state) {
                 case 'connecting':
-                    document.getElementById("noVNC_transition_text").innerHTML = _("Connecting...");
+                    document.getElementById("noVNC_transition_text").textContent = _("Connecting...");
                     document.documentElement.classList.add("noVNC_connecting");
                     break;
                 case 'connected':
@@ -431,7 +431,7 @@
                     break;
                 case 'disconnecting':
                     UI.connected = false;
-                    document.getElementById("noVNC_transition_text").innerHTML = _("Disconnecting...");
+                    document.getElementById("noVNC_transition_text").textContent = _("Disconnecting...");
                     document.documentElement.classList.add("noVNC_disconnecting");
                     break;
                 case 'disconnected':
@@ -531,7 +531,7 @@
                     break;
             }
 
-            statusElem.innerHTML = text;
+            statusElem.textContent = text;
             statusElem.classList.add("noVNC_open");
 
             // If no time was specified, show the status for 1.5 seconds
```
