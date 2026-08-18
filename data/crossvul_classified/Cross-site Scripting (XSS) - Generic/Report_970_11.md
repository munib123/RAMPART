# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 970_11
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `970_11`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 35-75 of the vulnerable file.

        assigned: false,

        messageName: 'create',

        isRemovable: false,

        data: function () {
            return _.extend({
                statusText: this.statusText,
                statusStyle: this.statusStyle
            }, Dep.prototype.data.call(this));
        },

        setup: function () {
            if (this.model.get('data')) {
                var data = this.model.get('data');

                this.assignedUserId = data.assignedUserId || null;
                this.assignedUserName = data.assignedUserName || null;

                this.messageData['assignee'] = '<a href="#User/view/' + this.assignedUserId + '">' + this.assignedUserName + '</a>';

                var isYou = false;
                if (this.isUserStream) {
                    if (this.assignedUserId == this.getUser().id) {
                        isYou = true;
                    }
                }

                if (this.assignedUserId) {
                    this.messageName = 'createAssigned';

                    if (this.isThis) {
                        this.messageName += 'This';

                        if (this.assignedUserId == this.model.get('createdById')) {
                            this.messageName += 'Self';
                        }
                    } else {
                        if (this.assignedUserId == this.model.get('createdById')) {
                            this.messageName += 'Self';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,7 +52,7 @@
                 this.assignedUserId = data.assignedUserId || null;
                 this.assignedUserName = data.assignedUserName || null;
 
-                this.messageData['assignee'] = '<a href="#User/view/' + this.assignedUserId + '">' + this.assignedUserName + '</a>';
+                this.messageData['assignee'] = '<a href="#User/view/' + this.assignedUserId + '">' + this.getHelper().escapeString(this.assignedUserName) + '</a>';
 
                 var isYou = false;
                 if (this.isUserStream) {
```
