# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 970_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `970_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 30-60 of the vulnerable file.


    return Dep.extend({

        template: 'notification/items/message',

        data: function () {
            return _.extend({
                style: this.style,
            }, Dep.prototype.data.call(this));
        },

        setup: function () {
            var data = this.model.get('data') || {};

            this.style = data.style || 'text-muted';

            this.messageTemplate = this.model.get('message') || data.message || '';

            this.userId = data.userId;

            this.messageData['entityType'] = Espo.Utils.upperCaseFirst((this.translate(data.entityType, 'scopeNames') || '').toLowerCase());

            this.messageData['user'] = '<a href="#User/view/' + data.userId + '">' + data.userName + '</a>';
            this.messageData['entity'] = '<a href="#'+data.entityType+'/view/' + data.entityId + '">' + data.entityName + '</a>';

            this.createMessage();
        }

    });
});

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,10 +47,10 @@
 
             this.userId = data.userId;
 
-            this.messageData['entityType'] = Espo.Utils.upperCaseFirst((this.translate(data.entityType, 'scopeNames') || '').toLowerCase());
+            this.messageData['entityType'] = this.getHelper().escapeString(Espo.Utils.upperCaseFirst((this.translate(data.entityType, 'scopeNames') || '').toLowerCase()));
 
-            this.messageData['user'] = '<a href="#User/view/' + data.userId + '">' + data.userName + '</a>';
-            this.messageData['entity'] = '<a href="#'+data.entityType+'/view/' + data.entityId + '">' + data.entityName + '</a>';
+            this.messageData['user'] = '<a href="#User/view/' + this.getHelper().escapeString(data.userId) + '">' + this.getHelper().escapeString(data.userName) + '</a>';
+            this.messageData['entity'] = '<a href="#'+this.getHelper().escapeString(data.entityType)+'/view/' + this.getHelper().escapeString(data.entityId) + '">' + this.getHelper().escapeString(data.entityName) + '</a>';
 
             this.createMessage();
         }
```
