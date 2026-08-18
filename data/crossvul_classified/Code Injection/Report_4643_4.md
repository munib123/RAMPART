# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 4643_4
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4643_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 1-33 of the vulnerable file.

'use strict';

const http = require('http');
const https = require('https');
const urllib = require('url');
const zlib = require('zlib');
const PassThrough = require('stream').PassThrough;
const Cookies = require('./cookies');
const packageData = require('../../package.json');

const MAX_REDIRECTS = 5;

module.exports = function(url, options) {
    return fetch(url, options);
};

module.exports.Cookies = Cookies;

function fetch(url, options) {
    options = options || {};

    options.fetchRes = options.fetchRes || new PassThrough();
    options.cookies = options.cookies || new Cookies();
    options.redirects = options.redirects || 0;
    options.maxRedirects = isNaN(options.maxRedirects) ? MAX_REDIRECTS : options.maxRedirects;

    if (options.cookie) {
        [].concat(options.cookie || []).forEach(cookie => {
            options.cookies.set(cookie, url);
        });
        options.cookie = false;
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,7 +10,7 @@
 
 const MAX_REDIRECTS = 5;
 
-module.exports = function(url, options) {
+module.exports = function (url, options) {
     return fetch(url, options);
 };
 
@@ -33,11 +33,7 @@
 
     let fetchRes = options.fetchRes;
     let parsed = urllib.parse(url);
-    let method =
-        (options.method || '')
-            .toString()
-            .trim()
-            .toUpperCase() || 'GET';
+    let method = (options.method || '').toString().trim().toUpperCase() || 'GET';
     let finished = false;
     let cookies;
     let body;
@@ -115,11 +111,7 @@
             headers['Content-Length'] = body.length;
         }
         // if method is not provided, use POST instead of GET
-        method =
-            (options.method || '')
-                .toString()
-                .trim()
-                .toUpperCase() || 'POST';
+        method = (options.method || '').toString().trim().toUpperCase() || 'POST';
     }
 
     let req;
```
