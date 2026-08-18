# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 970_9
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `970_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 35-75 of the vulnerable file.

        messageName: 'assign',

        data: function () {
            return _.extend({
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

            this.assignedUserId = data.assignedUserId || null;
            this.assignedUserName = data.assignedUserName || null;

            this.messageData['assignee'] = '<a href="#User/view/' + data.assignedUserId + '">' + data.assignedUserName + '</a>';

            if (this.isUserStream) {
                if (this.assignedUserId) {
                    if (this.assignedUserId == this.model.get('createdById')) {
                        this.messageName += 'Self';
                    } else {
                        if (this.assignedUserId == this.getUser().id) {
                            this.messageName += 'You';
                        }
                    }
                } else {
                    this.messageName += 'Void';
                }
            } else {
                if (this.assignedUserId) {
                    if (this.assignedUserId == this.model.get('createdById')) {
                        this.messageName += 'Self';
                    }
                } else {
                    this.messageName += 'Void';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,7 +52,7 @@
             this.assignedUserId = data.assignedUserId || null;
             this.assignedUserName = data.assignedUserName || null;
 
-            this.messageData['assignee'] = '<a href="#User/view/' + data.assignedUserId + '">' + data.assignedUserName + '</a>';
+            this.messageData['assignee'] = '<a href="#User/view/' + this.getHelper().escapeString(data.assignedUserId) + '">' + this.getHelper().escapeString(data.assignedUserName) + '</a>';
 
             if (this.isUserStream) {
                 if (this.assignedUserId) {
```
