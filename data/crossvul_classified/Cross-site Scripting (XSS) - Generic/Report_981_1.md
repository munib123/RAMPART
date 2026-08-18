# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 981_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `981_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 304-327 of the vulnerable file.


            if (color) {
                var $span = $('<span class="color-icon fas fa-square-full">');
                $span.css('color', color);
                if (additionalClassName) {
                    $span.addClass(additionalClassName);
                }
                html = $span.get(0).outerHTML;
            }

            if (!noWhiteSpace) {
                if (html) html += '&nbsp;';
            }

            return html;
        },

        sanitizeHtml: function (text, options) {
            return DOMPurify.sanitize(text, options);
        },
    });

    return ViewHelper;
});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -321,6 +321,77 @@
         sanitizeHtml: function (text, options) {
             return DOMPurify.sanitize(text, options);
         },
+
+        moderateSanitizeHtml: function (value) {
+            value = value || '';
+            value = value.replace(/<[\/]{0,1}(base)[^><]*>/gi, '');
+            value = value.replace(/<[\/]{0,1}(object)[^><]*>/gi, '');
+            value = value.replace(/<[\/]{0,1}(embed)[^><]*>/gi, '');
+            value = value.replace(/<[\/]{0,1}(applet)[^><]*>/gi, '');
+            value = value.replace(/<[\/]{0,1}(iframe)[^><]*>/gi, '');
+            value = value.replace(/<[\/]{0,1}(script)[^><]*>/gi, '');
+            value = value.replace(/<[^><]*([^a-z]{1}on[a-z]+)=[^><]*>/gi, function (match) {
+                return match.replace(/[^a-z]{1}on[a-z]+=/gi, ' data-handler-stripped=');
+            });
+
+            value = this.stripEventHandlersInHtml(value);
+
+            value = value.replace(/href=" *javascript\:(.*?)"/gi, function(m, $1) {
+                return 'removed=""';
+            });
+            value = value.replace(/href=' *javascript\:(.*?)'/gi, function(m, $1) {
+                return 'removed=""';
+            });
+            value = value.replace(/src=" *javascript\:(.*?)"/gi, function(m, $1) {
+                return 'removed=""';
+            });
+            value = value.replace(/src=' *javascript\:(.*?)'/gi, function(m, $1) {
+                return 'removed=""';
+            });
+
+            return value;
+        },
+
+        stripEventHandlersInHtml: function (html) {
+            function stripHTML(){
+                html = html.slice(0, strip) + html.slice(j);
+                j = strip;
+                strip = false;
+            }
+            function isValidTagChar(str) {
+                return str.match(/[a-z?\\\/!]/i);
+            }
+            var strip = false;
+            var lastQuote = false;
+            for (var i = 0; i<html.length; i++){
+                if (html[i] === "<" && html[i+1] && isValidTagChar(html[i+1])) {
+                    i++;
+                    for (var j = i; j<html.length; j++){
+                        if (!lastQuote && html[j] === ">"){
+                            if (strip) {
+                                stripHTML();
+                            }
+                            i = j;
+                            break;
+                        }
+                        if (lastQuote === html[j]){
+                            lastQuote = false;
+                            continue;
+                        }
+                        if (!lastQuote && html[j-1] === "=" && (html[j] === "'" || html[j] === '"')){
+                            lastQuote = html[j];
+                        }
+                        if (!lastQuote && html[j-2] === " " && html[j-1] === "o" && html[j] === "n"){
+                            strip = j-2;
+                        }
+                        if (strip && html[j] === " " && !lastQuote){
+                            stripHTML();
+                        }
+                    }
+                }
+            }
+            return html;
+        },
     });
 
     return ViewHelper;
```
