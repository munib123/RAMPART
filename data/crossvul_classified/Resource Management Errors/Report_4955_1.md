# CrossVul Fix Pair: Resource Management Errors in javascript
**Pair ID:** 4955_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4955_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```javascript
Lines 1-40 of the vulnerable file.

'use strict';

// Load modules

const Sntp = require('sntp');
const Boom = require('boom');


// Declare internals

const internals = {};


exports.version = function () {

    return require('../package.json').version;
};


// Extract host and port from request

//                                            $1                            $2
internals.hostHeaderRegex = /^(?:(?:\r\n)?\s)*((?:[^:]+)|(?:\[[^\]]+\]))(?::(\d+))?(?:(?:\r\n)?\s)*$/;              // (IPv4, hostname)|(IPv6)


exports.parseHost = function (req, hostHeaderName) {

    hostHeaderName = (hostHeaderName ? hostHeaderName.toLowerCase() : 'host');
    const hostHeader = req.headers[hostHeaderName];
    if (!hostHeader) {
        return null;
    }

    const hostParts = hostHeader.match(internals.hostHeaderRegex);
    if (!hostParts) {
        return null;
    }

    return {
        name: hostParts[1],
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,6 +17,11 @@
 };
 
 
+exports.limits = {
+    maxMatchLength: 4096            // Limit the length of uris and headers to avoid a DoS attack on string matching
+};
+
+
 // Extract host and port from request
 
 //                                            $1                            $2
@@ -28,6 +33,10 @@
     hostHeaderName = (hostHeaderName ? hostHeaderName.toLowerCase() : 'host');
     const hostHeader = req.headers[hostHeaderName];
     if (!hostHeader) {
+        return null;
+    }
+
+    if (hostHeader.length > exports.limits.maxMatchLength) {
         return null;
     }
 
@@ -100,6 +109,10 @@
 };
 
 
+internals.authHeaderRegex = /^(\w+)(?:\s+(.*))?$/;                                      // Header: scheme[ something]
+internals.attributeRegex = /^[ \w\!#\$%&'\(\)\*\+,\-\.\/\:;<\=>\?@\[\]\^`\{\|\}~]+$/;   // !#$%&'()*+,-./:;<=>?@[]^_`{|}~ and space, a-z, A-Z, 0-9
+
+
 // Parse Hawk HTTP Authorization header
 
 exports.parseAuthorizationHeader = function (header, keys) {
@@ -110,7 +123,11 @@
         return Boom.unauthorized(null, 'Hawk');
     }
 
-    const headerParts = header.match(/^(\w+)(?:\s+(.*))?$/);       // Header: scheme[ something]
+    if (header.length > exports.limits.maxMatchLength) {
+        return Boom.badRequest('Header length too long');
+    }
+
+    const headerParts = header.match(internals.authHeaderRegex);
     if (!headerParts) {
         return Boom.badRequest('Invalid header syntax');
     }
@@ -136,9 +153,9 @@
             return;
         }
 
-        // Allowed attribute value characters: !#$%&'()*+,-./:;<=>?@[]^_`{|}~ and space, a-z, A-Z, 0-9
+        // Allowed attribute value characters
 
-        if ($2.match(/^[ \w\!#\$%&'\(\)\*\+,\-\.\/\:;<\=>\?@\[\]\^`\{\|\}~]+$/) === null) {
+        if ($2.match(internals.attributeRegex) === null) {
             errorMessage = 'Bad attribute value: ' + $1;
             return;
         }
```
