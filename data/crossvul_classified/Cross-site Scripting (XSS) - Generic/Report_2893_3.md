# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2893_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2893_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 100-140 of the vulnerable file.

            return result;
        }, []);
    };

    return is.array(choices) ? unifyChoiceArray(choices, nestingLevel) : unifyChoiceObject(choices, nestingLevel);
};

var select = function (isMultiple) {
    return function (options) {
        var opt = options || {};
        var w = {
            classes: opt.classes,
            type: isMultiple ? 'multipleSelect' : 'select'
        };
        var userAttrs = getUserAttrs(opt);
        w.toHTML = function (name, field) {
            var f = field || {};
            var choices = unifyChoices(f.choices, 1);
            var optionsHTML = renderChoices(choices, function render(choice) {
                if (choice.isNested) {
                    return tag('optgroup', { label: choice.label }, renderChoices(choice.choices, render));
                } else {
                    return tag('option', { value: choice.value, selected: !!isSelected(f.value, choice.value) }, choice.label);
                }
            });
            var attrs = {
                name: name,
                id: f.id === false ? false : (f.id || true),
                classes: w.classes
            };
            if (isMultiple) {
                attrs.multiple = true;
            }
            return tag('select', [attrs, userAttrs, w.attrs || {}], optionsHTML);
        };
        return w;
    };
};

exports.text = input('text');
exports.email = input('email');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -117,7 +117,7 @@
             var choices = unifyChoices(f.choices, 1);
             var optionsHTML = renderChoices(choices, function render(choice) {
                 if (choice.isNested) {
-                    return tag('optgroup', { label: choice.label }, renderChoices(choice.choices, render));
+                    return tag('optgroup', { label: choice.label }, renderChoices(choice.choices, render), true);
                 } else {
                     return tag('option', { value: choice.value, selected: !!isSelected(f.value, choice.value) }, choice.label);
                 }
@@ -130,7 +130,7 @@
             if (isMultiple) {
                 attrs.multiple = true;
             }
-            return tag('select', [attrs, userAttrs, w.attrs || {}], optionsHTML);
+            return tag('select', [attrs, userAttrs, w.attrs || {}], optionsHTML, true);
         };
         return w;
     };
```
