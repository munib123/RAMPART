# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 226_3
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `226_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 1-16 of the vulnerable file.

var exec = require('child_process').exec;

module.exports = function (iface, callback) {
    exec("ifconfig " + iface, function (err, out) {
        if (err) {
            callback(err, null);
            return;
        }
        var match = /[a-f0-9]{2}(:[a-f0-9]{2}){5}/.exec(out.toLowerCase());
        if (!match) {
            callback("did not find a mac address", null);
            return;
        }
        callback(null, match[0].toLowerCase());
    });
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
-var exec = require('child_process').exec;
+var execFile = require('child_process').execFile;
 
 module.exports = function (iface, callback) {
-    exec("ifconfig " + iface, function (err, out) {
+    execFile("ifconfig", [iface], function (err, out) {
         if (err) {
             callback(err, null);
             return;
```
