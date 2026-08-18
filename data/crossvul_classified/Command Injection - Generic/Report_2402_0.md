# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in javascript
**Pair ID:** 2402_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2402_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```javascript
Lines 1-29 of the vulnerable file.

'use strict';

var net = require('net'),
    util = require('util'),
    path = require('path'),
    shell = require('shelljs'),
    debug = require('debug')('dns-sync');

/**
 * Resolve hostname to IP address,
 * returns null in case of error
 */
module.exports = {
    resolve: function resolve(hostname) {
        var output,
            nodeBinary = process.execPath,
            scriptPath = path.join(__dirname, "../scripts/dns-lookup-script"),
            response,
            cmd = util.format('"%s" "%s" %s', nodeBinary, scriptPath, hostname);

        response = shell.exec(cmd, {silent: true});
        if (response && response.code === 0) {
            output = response.output;
            if (output && net.isIP(output)) {
                return output;
            }
        }
        debug('hostname', "fail to resolve hostname " + hostname);
        return null;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,6 +6,12 @@
     shell = require('shelljs'),
     debug = require('debug')('dns-sync');
 
+//source - http://stackoverflow.com/questions/106179/regular-expression-to-match-dns-hostname-or-ip-address
+var ValidHostnameRegex = new RegExp("^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$");
+
+function isValidHostName(hostname) {
+    return ValidHostnameRegex.test(hostname);
+}
 /**
  * Resolve hostname to IP address,
  * returns null in case of error
@@ -13,8 +19,14 @@
 module.exports = {
     resolve: function resolve(hostname) {
         var output,
-            nodeBinary = process.execPath,
-            scriptPath = path.join(__dirname, "../scripts/dns-lookup-script"),
+            nodeBinary = process.execPath;
+
+        if (!isValidHostName(hostname)) {
+            console.error('Invalid hostname:', hostname);
+            return null;
+        }
+
+        var scriptPath = path.join(__dirname, "../scripts/dns-lookup-script"),
             response,
             cmd = util.format('"%s" "%s" %s', nodeBinary, scriptPath, hostname);
 
```
