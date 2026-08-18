# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 970_17
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `970_17`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 39-68 of the vulnerable file.

                style: this.style,
                statusText: this.statusText,
            }, Dep.prototype.data.call(this));
        },

        init: function () {
            if (this.getUser().isAdmin()) {
                this.isRemovable = true;
            }
            Dep.prototype.init.call(this);
        },

        setup: function () {
            var data = this.model.get('data');

            var field = data.field;
            var value = data.value;

            this.style = data.style || 'default';

            this.statusText = this.getLanguage().translateOption(value, field, this.model.get('parentType'));

            this.messageData['field'] = this.translate(field, 'fields', this.model.get('parentType')).toLowerCase();

            this.createMessage();
        },

    });
});

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,7 +56,7 @@
 
             this.style = data.style || 'default';
 
-            this.statusText = this.getLanguage().translateOption(value, field, this.model.get('parentType'));
+            this.statusText = this.getHelper().escapeString(this.getLanguage().translateOption(value, field, this.model.get('parentType')));
 
             this.messageData['field'] = this.translate(field, 'fields', this.model.get('parentType')).toLowerCase();
 
```
