# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2510_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2510_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 39-79 of the vulnerable file.


/**
 * Embedded JavaScript templating engine.
 *
 * @module ejs
 * @public
 */

var fs = require('fs');
var path = require('path');
var utils = require('./utils');

var scopeOptionWarned = false;
var _VERSION_STRING = require('../package.json').version;
var _DEFAULT_DELIMITER = '%';
var _DEFAULT_LOCALS_NAME = 'locals';
var _REGEX_STRING = '(<%%|%%>|<%=|<%-|<%_|<%#|<%|%>|-%>|_%>)';
var _OPTS = [ 'cache', 'filename', 'delimiter', 'scope', 'context',
        'debug', 'compileDebug', 'client', '_with', 'root', 'rmWhitespace',
        'strict', 'localsName'];
var _BOM = /^\uFEFF/;

/**
 * EJS template function cache. This can be a LRU object from lru-cache NPM
 * module. By default, it is {@link module:utils.cache}, a simple in-process
 * cache that grows continuously.
 *
 * @type {Cache}
 */

exports.cache = utils.cache;

/**
 * Name of the object containing the locals.
 *
 * This variable is overridden by {@link Options}`.localsName` if it is not
 * `undefined`.
 *
 * @type {String}
 * @public
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,6 +56,12 @@
 var _OPTS = [ 'cache', 'filename', 'delimiter', 'scope', 'context',
         'debug', 'compileDebug', 'client', '_with', 'root', 'rmWhitespace',
         'strict', 'localsName'];
+var _OPTS_IN_DATA_BLACKLIST = {
+      cache: true,
+      filename: true,
+      root: true,
+      localsName: true
+    };
 var _BOM = /^\uFEFF/;
 
 /**
@@ -268,11 +274,9 @@
 function cpOptsInData(data, opts) {
   _OPTS.forEach(function (p) {
     if (typeof data[p] != 'undefined') {
-      // Disallow setting the root opt for includes via a passed data obj
-      // Unsanitized, parameterized use of `render` could allow the
-      // include directory to be reset, opening up the possibility of
-      // remote code execution
-      if (p == 'root') {
+      // Disallow passing potentially dangerous opts in the data
+      // These opts should not be settable via a `render` call
+      if (_OPTS_IN_DATA_BLACKLIST[p]) {
         return;
       }
       opts[p] = data[p];
```
