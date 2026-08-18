# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 970_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `970_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 23-50 of the vulnerable file.

 * Section 5 of the GNU General Public License version 3.
 *
 * In accordance with Section 7(b) of the GNU General Public License version 3,
 * these Appropriate Legal Notices must retain the display of the "EspoCRM" word.
 ************************************************************************/

Espo.define('views/notification/items/assign', 'views/notification/items/base', function (Dep) {

    return Dep.extend({

        messageName: 'assign',

        template: 'notification/items/assign',

        setup: function () {
            var data = this.model.get('data') || {};

            this.userId = data.userId;

            this.messageData['entityType'] = Espo.Utils.upperCaseFirst((this.translate(data.entityType, 'scopeNames') || '').toLowerCase());
            this.messageData['entity'] = '<a href="#' + data.entityType + '/view/' + data.entityId + '">' + data.entityName + '</a>';

            this.createMessage();
        },

    });
});

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,7 +40,7 @@
             this.userId = data.userId;
 
             this.messageData['entityType'] = Espo.Utils.upperCaseFirst((this.translate(data.entityType, 'scopeNames') || '').toLowerCase());
-            this.messageData['entity'] = '<a href="#' + data.entityType + '/view/' + data.entityId + '">' + data.entityName + '</a>';
+            this.messageData['entity'] = '<a href="#' + this.getHelper().escapeString(data.entityType) + '/view/' + this.getHelper().escapeString(data.entityId) + '">' + this.getHelper().escapeString(data.entityName) + '</a>';
 
             this.createMessage();
         },
```
