# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in javascript
**Pair ID:** 3935_3
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3935_3`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```javascript
Lines 1-30 of the vulnerable file.

'use strict';

var util = require('util'),
    path = require('path'),
    shell = require('shelljs'),
    debug = require('debug')('dns-sync');

//source - http://stackoverflow.com/questions/106179/regular-expression-to-match-dns-hostname-or-ip-address
var ValidHostnameRegex = new RegExp("^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$");

function isValidHostName(hostname) {
    return ValidHostnameRegex.test(hostname);
}
/**
 * Resolve hostname to IP address,
 * returns null in case of error
 */
module.exports = {
    lookup: function lookup(hostname) {
        return module.exports.resolve(hostname);
    },
    resolve: function resolve(hostname, type) {
        var nodeBinary = process.execPath;

        if (!isValidHostName(hostname)) {
            console.error('Invalid hostname:', hostname);
            return null;
        }

        var scriptPath = path.join(__dirname, "../scripts/dns-lookup-script"),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,6 +7,20 @@
 
 //source - http://stackoverflow.com/questions/106179/regular-expression-to-match-dns-hostname-or-ip-address
 var ValidHostnameRegex = new RegExp("^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$");
+
+// https://nodejs.org/api/dns.html#dns_dns_resolve_hostname_rrtype_callback
+var RRecordTypes = [
+    'A',
+    'AAAA',
+    'NS',
+    'NAPTR',
+    'CNAME',
+    'SOA',
+    'SRV',
+    'PTR',
+    'MX',
+    'TXT',
+    'ANY'];
 
 function isValidHostName(hostname) {
     return ValidHostnameRegex.test(hostname);
@@ -26,6 +40,10 @@
             console.error('Invalid hostname:', hostname);
             return null;
         }
+        if (typeof type !== 'undefined' && RRecordTypes.indexOf(type) === -1) {
+            console.error('Invalid rrtype:', type);
+            return null;
+        }
 
         var scriptPath = path.join(__dirname, "../scripts/dns-lookup-script"),
             response,
```
