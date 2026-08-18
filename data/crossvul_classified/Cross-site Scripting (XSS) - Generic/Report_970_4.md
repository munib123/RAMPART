# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 970_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `970_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 29-64 of the vulnerable file.

Espo.define('views/notification/items/email-received', 'views/notification/items/base', function (Dep) {

    return Dep.extend({

        messageName: 'emailReceived',

        template: 'notification/items/email-received',

        data: function () {
            return _.extend({
                emailId: this.emailId,
                emailName: this.emailName
            }, Dep.prototype.data.call(this));
        },

        setup: function () {
            var data = this.model.get('data') || {};

            this.userId = data.userId;

            this.messageData['entityType'] = Espo.Utils.upperCaseFirst((this.translate(data.entityType, 'scopeNames') || '').toLowerCase());
            if (data.personEntityId) {
                this.messageData['from'] = '<a href="#' + data.personEntityType + '/view/' + data.personEntityId + '">' + data.personEntityName + '</a>';
            } else {
                this.messageData['from'] = data.fromString || this.translate('empty address');
            }

            this.emailId = data.emailId;
            this.emailName = data.emailName;

            this.createMessage();
        }

    });
});

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,19 +46,18 @@
 
             this.userId = data.userId;
 
-            this.messageData['entityType'] = Espo.Utils.upperCaseFirst((this.translate(data.entityType, 'scopeNames') || '').toLowerCase());
+            this.messageData['entityType'] = this.getHelper().escapeString(Espo.Utils.upperCaseFirst((this.translate(data.entityType, 'scopeNames') || '').toLowerCase()));
             if (data.personEntityId) {
-                this.messageData['from'] = '<a href="#' + data.personEntityType + '/view/' + data.personEntityId + '">' + data.personEntityName + '</a>';
+                this.messageData['from'] = '<a href="#' + this.getHelper().escapeString(data.personEntityType) + '/view/' + this.getHelper().escapeString(data.personEntityId) + '">' + this.getHelper().escapeString(data.personEntityName) + '</a>';
             } else {
-                this.messageData['from'] = data.fromString || this.translate('empty address');
+                this.messageData['from'] = this.getHelper().escapeString(data.fromString || this.translate('empty address'));
             }
 
-            this.emailId = data.emailId;
-            this.emailName = data.emailName;
+            this.emailId = this.getHelper().escapeString(data.emailId);
+            this.emailName = this.getHelper().escapeString(data.emailName);
 
             this.createMessage();
         }
 
     });
 });
-
```
