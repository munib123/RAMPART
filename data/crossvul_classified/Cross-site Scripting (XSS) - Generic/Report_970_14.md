# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 970_14
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `970_14`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 59-99 of the vulnerable file.

                this.messageName = 'mentionInPostTarget';
            }

            if (this.isUserStream) {
                if (this.options.userId == this.getUser().id) {
                    if (!this.model.get('parentId')) {
                        this.messageName = 'mentionYouInPostTarget';
                        if (this.model.get('isGlobal')) {
                            this.messageName = 'mentionYouInPostTargetAll';
                        } else {
                            this.messageName = 'mentionYouInPostTarget';
                            if (this.model.has('teamsIds') && this.model.get('teamsIds').length) {
                                var teamIdList = this.model.get('teamsIds');
                                var teamNameHash = this.model.get('teamsNames') || {};

                                var targetHtml = '';
                                var teamHtmlList = [];
                                teamIdList.forEach(function (teamId) {
                                    var teamName = teamNameHash[teamId];
                                    if (teamName) {
                                        teamHtmlList.push('<a href="#Team/view/' + teamId + '">' + teamName + '</a>');
                                    }
                                }, this);

                                this.messageData['target'] = teamHtmlList.join(', ');
                            } else if (this.model.has('usersIds') && this.model.get('usersIds').length) {
                                var userIdList = this.model.get('usersIds');
                                var userNameHash = this.model.get('usersNames') || {};

                                if (userIdList.length === 1 && userIdList[0] === this.model.get('createdById')) {
                                    this.messageName = 'mentionYouInPostTargetNoTarget';
                                } else {
                                    var userHtml = '';
                                    var userHtmlList = [];
                                    userIdList.forEach(function (userId) {
                                        var userName = userNameHash[userId];
                                        if (userName) {
                                            userHtmlList.push('<a href="#User/view/' + userId + '">' + userName + '</a>');
                                        }
                                    }, this);
                                    this.messageData['target'] = userHtmlList.join(', ');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -76,7 +76,7 @@
                                 teamIdList.forEach(function (teamId) {
                                     var teamName = teamNameHash[teamId];
                                     if (teamName) {
-                                        teamHtmlList.push('<a href="#Team/view/' + teamId + '">' + teamName + '</a>');
+                                        teamHtmlList.push('<a href="#Team/view/' + this.getHelper().escapeString(teamId) + '">' + this.getHelper().escapeString(teamName) + '</a>');
                                     }
                                 }, this);
 
@@ -93,7 +93,7 @@
                                     userIdList.forEach(function (userId) {
                                         var userName = userNameHash[userId];
                                         if (userName) {
-                                            userHtmlList.push('<a href="#User/view/' + userId + '">' + userName + '</a>');
+                                            userHtmlList.push('<a href="#User/view/' + this.getHelper().escapeString(userId) + '">' + this.getHelper().escapeString(userName) + '</a>');
                                         }
                                     }, this);
                                     this.messageData['target'] = userHtmlList.join(', ');
@@ -113,4 +113,3 @@
 
     });
 });
-
```
