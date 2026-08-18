# CrossVul Fix Pair: Improper Authentication in javascript
**Pair ID:** 2029_5
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2029_5`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```javascript
Lines 1-34 of the vulnerable file.


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
    }).directive('gogoTerminal', function(log) {
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

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,7 +11,7 @@
         when('/gogo', {
             templateUrl: 'hawtio-karaf-terminal/app/html/gogo.html'
           });
-    }).directive('gogoTerminal', function(log) {
+    }).directive('gogoTerminal', function(log, userDetails) {
       return {
         restrict: 'A',
         link: function(scope, element, attrs) {
@@ -50,7 +50,9 @@
             'min-height': cssHeight
           });
 
-          gogo.Terminal(element.get(0), width, height);
+          var authHeader = Core.getBasicAuthHeader(userDetails.username, userDetails.password);
+
+          gogo.Terminal(element.get(0), width, height, authHeader);
 
           scope.$on("$destroy", function(e) {
             document.onkeypress = null;
```
