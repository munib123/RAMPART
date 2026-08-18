# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in javascript
**Pair ID:** 2028_3
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2028_3`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```javascript
Lines 1-38 of the vulnerable file.


var Gogo = (function() {
  // create our angular module and tell angular what route(s) it will handle
  var pluginName = "gogo";

  var simplePlugin = angular.module(pluginName, ['hawtioCore'])
    .factory('log', function() {
      return Logger.get("Gogo");
    }).config(function($routeProvider) {
      $routeProvider.
        when('/gogo', {
            templateUrl: 'hawtio-karaf-terminal/app/html/gogo.html'
          });
    }).directive('gogoTerminal', function(log, userDetails) {
      return {
        restrict: 'A',
        link: function(scope, element, attrs) {

          var width = 120;
          var height = 39;

          var div = $('<div class="terminal">A</div>').css({
            position: 'absolute',
            left: -1000,
            top: -1000,
            display: 'block',
            padding: 0,
            margin: 0,
            'font-family': 'monospace'
          }).appendTo($('body'));

          var charWidth = div.width();
          var charHeight = div.height();

          div.remove();

          // compensate for internal horizontal padding
          var cssWidth = width * charWidth + 20;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,6 +15,34 @@
       return {
         restrict: 'A',
         link: function(scope, element, attrs) {
+
+          scope.$on("$destroy", function(e) {
+            scope.destroyed = true;
+            document.onkeypress = null;
+            document.onkeydown = null;
+            if (!('term' in scope)) {
+              return;
+            }
+            var url = "hawtio-karaf-terminal/auth/logout/";
+            delete scope.term;
+            $.ajax(url, {
+              type: "POST",
+              success: function (response) {
+                log.debug("logged out of terminal");
+                Core.$apply(scope);
+              },
+              error: function (xhr, textStatus, error) {
+                log.info("Failed to log out of terminal: ", error);
+              },
+              beforeSend: function (xhr) {
+                xhr.setRequestHeader('Authorization', authHeader);
+              }
+            })
+          });
+
+          if (scope.destroyed) {
+            return;
+          }
 
           var width = 120;
           var height = 39;
@@ -52,11 +80,32 @@
 
           var authHeader = Core.getBasicAuthHeader(userDetails.username, userDetails.password);
 
-          gogo.Terminal(element.get(0), width, height, authHeader);
+          var url = "hawtio-karaf-terminal/auth/login/";
 
-          scope.$on("$destroy", function(e) {
-            document.onkeypress = null;
-            document.onkeydown = null;
+          $.ajax(url, {
+            type: "POST",
+            success: function (response) {
+              if (scope.destroyed) {
+                log.debug("Scope's been destroyed since we made our request, let's not create a terminal instance");
+                return;
+              }
+              log.debug("got back response: ", response);
+              if ('term' in scope) {
+                log.debug("Previous terminal created, let's clean it up");
+                document.onkeypress = null;
+                document.onkeydown = null;
+                delete scope.term;
+              }
+              scope.term = gogo.Terminal(element.get(0), width, height, response['token']);
+              Core.$apply(scope);
+
+            },
+            error: function (xhr, textStatus, error) {
+              log.warn("Failed to log into terminal: ", error);
+            },
+            beforeSend: function (xhr) {
+              xhr.setRequestHeader('Authorization', authHeader);
+            }
           });
 
         }
```
