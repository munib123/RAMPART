# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 226_4
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `226_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 1-21 of the vulnerable file.

var exec = require('child_process').exec;

var regexRegex = /[-\/\\^$*+?.()|[\]{}]/g;

function escape(string) {
    return string.replace(regexRegex, '\\$&');
}

module.exports = function (iface, callback) {
    exec("ipconfig /all", function (err, out) {
        if (err) {
            callback(err, null);
            return;
        }
        var match = new RegExp(escape(iface)).exec(out);
        if (!match) {
            callback("did not find interface in `ipconfig /all`", null);
            return;
        }
        out = out.substring(match.index + iface.length);
        match = /[A-Fa-f0-9]{2}(\-[A-Fa-f0-9]{2}){5}/.exec(out);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-var exec = require('child_process').exec;
+var execFile = require('child_process').execFile;
 
 var regexRegex = /[-\/\\^$*+?.()|[\]{}]/g;
 
@@ -7,7 +7,7 @@
 }
 
 module.exports = function (iface, callback) {
-    exec("ipconfig /all", function (err, out) {
+    execFile("ipconfig", ["/all"], function (err, out) {
         if (err) {
             callback(err, null);
             return;
```
