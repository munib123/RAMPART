# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 970_13
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `970_13`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 48-83 of the vulnerable file.

            var data = this.model.get('data') || {};

            this.emailId = data.emailId;
            this.emailName = data.emailName;

            if (
                this.parentModel
                &&
                (this.model.get('parentType') == this.parentModel.name && this.model.get('parentId') == this.parentModel.id)
            ) {
                if (this.model.get('post')) {
                    this.createField('post', null, null, 'views/stream/fields/post');
                    this.hasPost = true;
                }
                if ((this.model.get('attachmentsIds') || []).length) {
                    this.createField('attachments', 'attachmentMultiple', {}, 'views/stream/fields/attachment-multiple');
                    this.hasAttachments = true;
                }
            }

            this.messageData['email'] = '<a href="#Email/view/' + data.emailId + '">' + data.emailName + '</a>';

            this.messageName = 'emailSent';

            this.messageData['by'] = '<a href="#'+data.personEntityType+'/view/' + data.personEntityId + '">' + data.personEntityName + '</a>';


            if (this.isThis) {
                this.messageName += 'This';
            }

            this.createMessage();
        },

    });
});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,11 +65,11 @@
                 }
             }
 
-            this.messageData['email'] = '<a href="#Email/view/' + data.emailId + '">' + data.emailName + '</a>';
+            this.messageData['email'] = '<a href="#Email/view/' + this.getHelper().escapeString(data.emailId) + '">' + this.getHelper().escapeString(data.emailName) + '</a>';
 
             this.messageName = 'emailSent';
 
-            this.messageData['by'] = '<a href="#'+data.personEntityType+'/view/' + data.personEntityId + '">' + data.personEntityName + '</a>';
+            this.messageData['by'] = '<a href="#'+this.getHelper().escapeString(data.personEntityType)+'/view/' + this.getHelper().escapeString(data.personEntityId) + '">' + this.getHelper().escapeString(data.personEntityName) + '</a>';
 
 
             if (this.isThis) {
```
