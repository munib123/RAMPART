# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4513_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4513_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 890-909 of the vulnerable file.

                            if (str[i + 1] === ",") result += "null,";
                            i++;
                        }
                    } else if (str[i] === "]" && i === str.length - 1) {
                        result += "]";
                        return result;
                    }
                }
            }
            throw new Error("Broken JSON array near " + result);
        }
    }

    // Global function
    window.ocJSON = function(json) {
        var jsonString = parse(json);
        return JSON.parse(jsonString);
    };

}(window);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -907,3 +907,71 @@
     };
 
 }(window);
+
+/*
+ * October CMS jQuery HTML Sanitizer
+ * @see https://gist.github.com/ufologist/5a0da51b2b9ef1b861c30254172ac3c9
+ */
++function(window) { "use strict";
+
+    function trimAttributes(node) {
+        $.each(node.attributes, function() {
+            var attrName = this.name;
+            var attrValue = this.value;
+
+            /*
+             * remove attributes where the names start with "on" (for example: onload, onerror...)
+             * remove attributes where the value starts with the "javascript:" pseudo protocol (for example href="javascript:alert(1)")
+             */
+            if (attrName.indexOf('on') == 0 || attrValue.indexOf('javascript:') == 0) {
+                $(node).removeAttr(attrName);
+            }
+        });
+    }
+
+    function sanitize(html) {
+        /*
+         * [jQuery.parseHTML(data [, context ] [, keepScripts ])](http://api.jquery.com/jQuery.parseHTML/) added: 1.8
+         * Parses a string into an array of DOM nodes.
+         *
+         * By default, the context is the current document if not specified or given as null or undefined. If the HTML was to be used
+         * in another document such as an iframe, that frame's document could be used.
+         *
+         * As of 3.0 the default behavior is changed.
+         *
+         * If the context is not specified or given as null or undefined, a new document is used.
+         * This can potentially improve security because inline events will not execute when the HTML is parsed. Once the parsed HTML
+         * is injected into a document it does execute, but this gives tools a chance to traverse the created DOM and remove anything
+         * deemed unsafe. This improvement does not apply to internal uses of jQuery.parseHTML as they usually pass in the current
+         * document. Therefore, a statement like $( "#log" ).append( $( htmlString ) ) is still subject to the injection of malicious code.
+         *
+         * without context do not execute script
+         * $.parseHTML('<div><img src=1 onerror=alert(1)></div>');
+         * $.parseHTML('<div><img src=1 onerror=alert(2)></div>', null);
+         *
+         * with context document execute script!
+         * $.parseHTML('<div><img src=1 onerror=alert(3)></div>', document);
+         *
+         * Most jQuery APIs that accept HTML strings will run scripts that are included in the HTML. jQuery.parseHTML does not run scripts
+         * in the parsed HTML unless keepScripts is explicitly true. However, it is still possible in most environments to execute scripts
+         * indirectly, for example via the <img onerror> attribute.
+         *
+         * will return []
+         * $.parseHTML('<script>alert(1)<\/script>', null, false);
+         *
+         * will return [script DOM element]
+         * $.parseHTML('<script>alert(1)<\/script>', null, true);
+         */
+        var output = $($.parseHTML('<div>' + html + '</div>', null, false));
+        output.find('*').each(function() {
+            trimAttributes(this);
+        });
+        return output.html();
+    }
+
+    // Global function
+    window.ocSanitize = function(html) {
+        return sanitize(html)
+    };
+
+}(window);
```
