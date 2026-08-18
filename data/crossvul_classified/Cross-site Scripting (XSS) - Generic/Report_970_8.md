# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 970_8
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `970_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 68-108 of the vulnerable file.

                        this.isThis = false;
                    }
                }
            }

            if (this.getUser().isAdmin()) {
                this.isRemovable = true;
            }

            if (this.messageName && this.isThis) {
                this.messageName += 'This';
            }

            if (!this.isThis) {
                this.createField('parent');
            }

            this.messageData = {
                'user': 'field:createdBy',
                'entity': 'field:parent',
                'entityType': this.translateEntityType(this.model.get('parentType')),
            };

            if (!this.options.noEdit && (this.isEditable || this.isRemovable)) {
                this.createView('right', 'views/stream/row-actions/default', {
                    el: this.options.el + ' .right-container',
                    acl: this.options.acl,
                    model: this.model,
                    isEditable: this.isEditable,
                    isRemovable: this.isRemovable
                });
            }
        },

        translateEntityType: function (entityType, isPlural) {
            var string;

            if (!isPlural) {
                string = (this.translate(entityType, 'scopeNames') || '');
            } else {
                string = (this.translate(entityType, 'scopeNamesPlural') || '');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -85,7 +85,7 @@
             this.messageData = {
                 'user': 'field:createdBy',
                 'entity': 'field:parent',
-                'entityType': this.translateEntityType(this.model.get('parentType')),
+                'entityType': this.getHelper().escapeString(this.translateEntityType(this.model.get('parentType'))),
             };
 
             if (!this.options.noEdit && (this.isEditable || this.isRemovable)) {
```
