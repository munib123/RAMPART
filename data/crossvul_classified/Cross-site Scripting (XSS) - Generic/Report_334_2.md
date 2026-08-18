# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 334_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `334_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-23 of the vulnerable file.

angular.module('portainer.app')
.controller('TeamsController', ['$q', '$scope', '$state', 'TeamService', 'UserService', 'ModalService', 'Notifications', 'Authentication',
function ($q, $scope, $state, TeamService, UserService, ModalService, Notifications, Authentication) {
  $scope.state = {
    actionInProgress: false
  };

  $scope.formValues = {
    Name: '',
    Leaders: []
  };

  $scope.checkNameValidity = function(form) {
    var valid = true;
    for (var i = 0; i < $scope.teams.length; i++) {
      if ($scope.formValues.Name === $scope.teams[i].Name) {
        valid = false;
        break;
      }
    }
    form.team_name.$setValidity('validName', valid);
  };

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 angular.module('portainer.app')
-.controller('TeamsController', ['$q', '$scope', '$state', 'TeamService', 'UserService', 'ModalService', 'Notifications', 'Authentication',
-function ($q, $scope, $state, TeamService, UserService, ModalService, Notifications, Authentication) {
+.controller('TeamsController', ['$q', '$scope', '$state', '$sanitize', 'TeamService', 'UserService', 'ModalService', 'Notifications', 'Authentication',
+function ($q, $scope, $state, $sanitize, TeamService, UserService, ModalService, Notifications, Authentication) {
   $scope.state = {
     actionInProgress: false
   };
@@ -22,7 +22,7 @@
   };
 
   $scope.addTeam = function() {
-    var teamName = $scope.formValues.Name;
+    var teamName = $sanitize($scope.formValues.Name);
     var leaderIds = [];
     angular.forEach($scope.formValues.Leaders, function(user) {
       leaderIds.push(user.Id);
```
