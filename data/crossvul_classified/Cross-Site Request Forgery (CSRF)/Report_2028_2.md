# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in javascript
**Pair ID:** 2028_2
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2028_2`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```javascript
Lines 1-29 of the vulnerable file.


//
// Based on http://antony.lesuisse.org/software/ajaxterm/
//  Public Domain License
//

gogo = { };

gogo.Terminal_ctor = function(div, width, height, authHeader) {

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
 
-gogo.Terminal_ctor = function(div, width, height, authHeader) {
+gogo.Terminal_ctor = function(div, width, height, token) {
 
    var query0 = "w=" + width + "&h=" + height;
    var query1 = query0 + "&k=";
@@ -47,7 +47,7 @@
                force = 0;
            }
            r.open("POST", "hawtio-karaf-terminal/term", true);
-           r.setRequestHeader('Authorization', authHeader);
+           r.setRequestHeader('LoginToken', token);
            r.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            r.onreadystatechange = function () {
                if (r.readyState == 4) {
@@ -224,7 +224,7 @@
 
 }
 
-gogo.Terminal = function(div, width, height, authHeader) {
-   return new this.Terminal_ctor(div, width, height, authHeader);
+gogo.Terminal = function(div, width, height, token) {
+   return new this.Terminal_ctor(div, width, height, token);
 }
 
```
