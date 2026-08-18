# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 970_15
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `970_15`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 68-108 of the vulnerable file.

                }
            }, this);

            if (!this.model.get('parentId')) {
                if (this.model.get('isGlobal')) {
                    this.messageName = 'postTargetAll';
                } else {
                    if (this.model.has('teamsIds') && this.model.get('teamsIds').length) {
                        var teamIdList = this.model.get('teamsIds');
                        var teamNameHash = this.model.get('teamsNames') || {};
                        this.messageName = 'postTargetTeam';
                        if (teamIdList.length > 1) {
                            this.messageName = 'postTargetTeams';
                        }

                        var targetHtml = '';
                        var teamHtmlList = [];
                        teamIdList.forEach(function (teamId) {
                            var teamName = teamNameHash[teamId];
                            if (teamName) {
                                teamHtmlList.push('<a href="#Team/view/' + teamId + '">' + teamName + '</a>');
                            }
                        }, this);

                        this.messageData['target'] = teamHtmlList.join(', ');
                    } else if (this.model.has('portalsIds') && this.model.get('portalsIds').length) {
                        var portalIdList = this.model.get('portalsIds');
                        var portalNameHash = this.model.get('portalsNames') || {};
                        this.messageName = 'postTargetPortal';
                        if (portalIdList.length > 1) {
                            this.messageName = 'postTargetPortals';
                        }

                        var targetHtml = '';
                        var portalHtmlList = [];
                        portalIdList.forEach(function (portalId) {
                            var portalName = portalNameHash[portalId];
                            if (portalName) {
                                portalHtmlList.push('<a href="#Portal/view/' + portalId + '">' + portalName + '</a>');
                            }
                        }, this);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -85,7 +85,7 @@
                         teamIdList.forEach(function (teamId) {
                             var teamName = teamNameHash[teamId];
                             if (teamName) {
-                                teamHtmlList.push('<a href="#Team/view/' + teamId + '">' + teamName + '</a>');
+                                teamHtmlList.push('<a href="#Team/view/' + this.getHelper().escapeString(teamId) + '">' + this.getHelper().escapeString(teamName) + '</a>');
                             }
                         }, this);
 
@@ -103,7 +103,7 @@
                         portalIdList.forEach(function (portalId) {
                             var portalName = portalNameHash[portalId];
                             if (portalName) {
-                                portalHtmlList.push('<a href="#Portal/view/' + portalId + '">' + portalName + '</a>');
+                                portalHtmlList.push('<a href="#Portal/view/' + this.getHelper().escapeString(portalId) + '">' + this.getHelper().escapeString(portalName) + '</a>');
                             }
                         }, this);
 
@@ -135,7 +135,7 @@
                                     } else {
                                         var userName = userNameHash[userId];
                                         if (userName) {
-                                            userHtmlList.push('<a href="#User/view/' + userId + '">' + userName + '</a>');
+                                            userHtmlList.push('<a href="#User/view/' + this.getHelper().escapeString(userId) + '">' + this.getHelper().escapeString(userName) + '</a>');
                                         }
                                     }
                                 }
```
