# CrossVul Fix Pair: Improper Authentication in javascript
**Pair ID:** 2029_4
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2029_4`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```javascript
Lines 1-29 of the vulnerable file.


//
// Based on http://antony.lesuisse.org/software/ajaxterm/
//  Public Domain License
//

gogo = { };

gogo.Terminal_ctor = function(div, width, height) {

   var query0 = "w=" + width + "&h=" + height;
   var query1 = query0 + "&k=";
   var buf = "";
   var timeout;
   var error_timeout;
   var keybuf = [];
   var sending = 0;
   var rmax = 1;
   var force = 1;

   var dstat = document.createElement('pre');
   var sled = document.createElement('span');
   var sdebug = document.createElement('span');
   var dterm = document.createElement('div');

   function debug(s) {
       sdebug.innerHTML = s;
   }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,7 +6,7 @@
 
 gogo = { };
 
-gogo.Terminal_ctor = function(div, width, height) {
+gogo.Terminal_ctor = function(div, width, height, authHeader) {
 
    var query0 = "w=" + width + "&h=" + height;
    var query1 = query0 + "&k=";
@@ -47,6 +47,7 @@
                force = 0;
            }
            r.open("POST", "hawtio-karaf-terminal/term", true);
+           r.setRequestHeader('Authorization', authHeader);
            r.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            r.onreadystatechange = function () {
                if (r.readyState == 4) {
@@ -223,7 +224,7 @@
 
 }
 
-gogo.Terminal = function(div, width, height) {
-   return new this.Terminal_ctor(div, width, height);
+gogo.Terminal = function(div, width, height, authHeader) {
+   return new this.Terminal_ctor(div, width, height, authHeader);
 }
 
```
