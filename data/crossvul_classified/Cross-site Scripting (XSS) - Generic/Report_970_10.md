# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 970_10
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `970_10`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 39-65 of the vulnerable file.

                relatedTypeString: this.translateEntityType(this.entityType),
                iconHtml: this.getIconHtml(this.entityType, this.entityId)
            }, Dep.prototype.data.call(this));
        },

        init: function () {
            if (this.getUser().isAdmin()) {
                this.isRemovable = true;
            }
            Dep.prototype.init.call(this);
        },

        setup: function () {
            var data = this.model.get('data') || {};

            this.entityType = this.model.get('relatedType') || data.entityType || null;
            this.entityId = this.model.get('relatedId') || data.entityId || null;
            this.entityName = this.model.get('relatedName') ||  data.entityName || null;

            this.messageData['relatedEntityType'] = this.translateEntityType(this.entityType);
            this.messageData['relatedEntity'] = '<a href="#' + this.entityType + '/view/' + this.entityId + '">' + this.entityName +'</a>';

            this.createMessage();
        }
    });
});

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,7 +56,7 @@
             this.entityName = this.model.get('relatedName') ||  data.entityName || null;
 
             this.messageData['relatedEntityType'] = this.translateEntityType(this.entityType);
-            this.messageData['relatedEntity'] = '<a href="#' + this.entityType + '/view/' + this.entityId + '">' + this.entityName +'</a>';
+            this.messageData['relatedEntity'] = '<a href="#' + this.getHelper().escapeString(this.entityType) + '/view/' + this.getHelper().escapeString(this.entityId) + '">' + this.getHelper().escapeString(this.entityName) +'</a>';
 
             this.createMessage();
         }
```
