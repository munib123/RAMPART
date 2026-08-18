# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2893_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2893_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 4-44 of the vulnerable file.

var wrapWith = function (tagName) {
    return function (name, field, options) {
        var opt = options || {};
        var wrappedContent = [];
        var errorHTML = opt.hideError ? '' : field.errorHTML();
        if (field.widget.type === 'multipleCheckbox' || field.widget.type === 'multipleRadio') {
            var fieldsetAttrs = { classes: [] };
            if (opt.fieldsetClasses) {
                fieldsetAttrs.classes = fieldsetAttrs.classes.concat(opt.fieldsetClasses);
            }
            var legendAttrs = { classes: [] };
            if (opt.legendClasses) {
                legendAttrs.classes = legendAttrs.classes.concat(opt.legendClasses);
            }

            var fieldset = tag('fieldset', fieldsetAttrs, [
                tag('legend', legendAttrs, field.labelText(name)),
                opt.errorAfterField ? '' : errorHTML,
                field.widget.toHTML(name, field),
                opt.errorAfterField ? errorHTML : ''
            ].join(''));
            wrappedContent.push(fieldset);
        } else {
            var fieldHTMLs = [field.labelHTML(name, field.id), field.widget.toHTML(name, field)];
            if (opt.labelAfterField) {
                fieldHTMLs.reverse();
            }
            if (opt.errorAfterField) {
                fieldHTMLs.push(errorHTML);
            } else {
                fieldHTMLs.unshift(errorHTML);
            }
            wrappedContent = wrappedContent.concat(fieldHTMLs);
        }
        return tag(tagName, { classes: field.classes() }, wrappedContent.join(''));
    };
};
exports.div = wrapWith('div');
exports.p = wrapWith('p');
exports.li = wrapWith('li');

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,7 +21,7 @@
                 opt.errorAfterField ? '' : errorHTML,
                 field.widget.toHTML(name, field),
                 opt.errorAfterField ? errorHTML : ''
-            ].join(''));
+            ].join(''), true);
             wrappedContent.push(fieldset);
         } else {
             var fieldHTMLs = [field.labelHTML(name, field.id), field.widget.toHTML(name, field)];
@@ -35,7 +35,7 @@
             }
             wrappedContent = wrappedContent.concat(fieldHTMLs);
         }
-        return tag(tagName, { classes: field.classes() }, wrappedContent.join(''));
+        return tag(tagName, { classes: field.classes() }, wrappedContent.join(''), true);
     };
 };
 exports.div = wrapWith('div');
@@ -45,7 +45,7 @@
 exports.table = function (name, field, options) {
     var opt = options || {};
 
-    var th = tag('th', {}, field.labelHTML(name, field.id));
+    var th = tag('th', {}, field.labelHTML(name, field.id), true);
 
     var tdContent = field.widget.toHTML(name, field);
 
@@ -58,7 +58,7 @@
         }
     }
 
-    var td = tag('td', {}, tdContent);
+    var td = tag('td', {}, tdContent, true);
 
-    return tag('tr', { classes: field.classes() }, th + td);
+    return tag('tr', { classes: field.classes() }, th + td, true);
 };
```
