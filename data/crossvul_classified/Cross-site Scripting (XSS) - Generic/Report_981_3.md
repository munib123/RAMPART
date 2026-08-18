# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 981_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `981_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 148-207 of the vulnerable file.

        },

        getValueForDisplay: function () {
            var value = Dep.prototype.getValueForDisplay.call(this);
            return this.sanitizeHtml(value);
        },

        sanitizeHtml: function (value) {
            if (value) {
                if (!this.htmlPurificationDisabled) {
                    value = this.getHelper().sanitizeHtml(value);
                } else {
                    value = this.sanitizeHtmlLight(value);
                }
            }
            return value || '';
        },


        sanitizeHtmlLight: function (value) {
            value = value || '';
            value = value.replace(/<[\/]{0,1}(base)[^><]*>/gi, '');
            value = value.replace(/<[\/]{0,1}(object)[^><]*>/gi, '');
            value = value.replace(/<[\/]{0,1}(embed)[^><]*>/gi, '');
            value = value.replace(/<[\/]{0,1}(applet)[^><]*>/gi, '');
            value = value.replace(/<[\/]{0,1}(iframe)[^><]*>/gi, '');
            value = value.replace(/<[\/]{0,1}(script)[^><]*>/gi, '');
            value = value.replace(/<[^><]*([^a-z]{1}on[a-z]+)=[^><]*>/gi, function (match) {
                return match.replace(/[^a-z]{1}on[a-z]+=/gi, ' data-handler-stripped=');
            });

            value = value.replace(/href=" *javascript\:(.*?)"/gi, function(m, $1) {
                return 'removed=""';
            });
            value = value.replace(/href=' *javascript\:(.*?)'/gi, function(m, $1) {
                return 'removed=""';
            });
            value = value.replace(/src=" *javascript\:(.*?)"/gi, function(m, $1) {
                return 'removed=""';
            });
            value = value.replace(/src=' *javascript\:(.*?)'/gi, function(m, $1) {
                return 'removed=""';
            });
            return value;
        },

        getValueForEdit: function () {
            var value = this.model.get(this.name) || '';
            return this.sanitizeHtmlLight(value);
        },

        afterRender: function () {
            Dep.prototype.afterRender.call(this);

            if (this.mode == 'edit') {
                this.$summernote = this.$el.find('.summernote');
            }

            var language = this.getConfig().get('language');

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -165,30 +165,7 @@
 
 
         sanitizeHtmlLight: function (value) {
-            value = value || '';
-            value = value.replace(/<[\/]{0,1}(base)[^><]*>/gi, '');
-            value = value.replace(/<[\/]{0,1}(object)[^><]*>/gi, '');
-            value = value.replace(/<[\/]{0,1}(embed)[^><]*>/gi, '');
-            value = value.replace(/<[\/]{0,1}(applet)[^><]*>/gi, '');
-            value = value.replace(/<[\/]{0,1}(iframe)[^><]*>/gi, '');
-            value = value.replace(/<[\/]{0,1}(script)[^><]*>/gi, '');
-            value = value.replace(/<[^><]*([^a-z]{1}on[a-z]+)=[^><]*>/gi, function (match) {
-                return match.replace(/[^a-z]{1}on[a-z]+=/gi, ' data-handler-stripped=');
-            });
-
-            value = value.replace(/href=" *javascript\:(.*?)"/gi, function(m, $1) {
-                return 'removed=""';
-            });
-            value = value.replace(/href=' *javascript\:(.*?)'/gi, function(m, $1) {
-                return 'removed=""';
-            });
-            value = value.replace(/src=" *javascript\:(.*?)"/gi, function(m, $1) {
-                return 'removed=""';
-            });
-            value = value.replace(/src=' *javascript\:(.*?)'/gi, function(m, $1) {
-                return 'removed=""';
-            });
-            return value;
+           return this.getHelper().moderateSanitizeHtml(value);
         },
 
         getValueForEdit: function () {
```
