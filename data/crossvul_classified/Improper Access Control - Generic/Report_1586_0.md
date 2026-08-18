# CrossVul Fix Pair: Improper Access Control in javascript
**Pair ID:** 1586_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1586_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```javascript
Lines 3-43 of the vulnerable file.

'use strict';


var utils        = require('./common/utils');
var helpers      = require('./helpers');
var Renderer     = require('./renderer');
var ParserCore   = require('./parser_core');
var ParserBlock  = require('./parser_block');
var ParserInline = require('./parser_inline');
var LinkifyIt    = require('linkify-it');
var mdurl        = require('mdurl');
var punycode     = require('punycode');


var config = {
  'default': require('./presets/default'),
  zero: require('./presets/zero'),
  commonmark: require('./presets/commonmark')
};


var BAD_PROTOCOLS    = [ 'vbscript', 'javascript', 'file' ];

function validateLink(url) {
  // url should be normalized at this point, and existing entities are decoded
  //
  var str = url.trim().toLowerCase();

  if (str.indexOf(':') >= 0 && BAD_PROTOCOLS.indexOf(str.split(':')[0]) >= 0) {
    return false;
  }
  return true;
}

var RECODE_HOSTNAME_FOR = [ 'http:', 'https:', 'mailto:' ];

function normalizeLink(url) {
  var parsed = mdurl.parse(url, true);

  if (parsed.hostname) {
    // Encode hostnames in urls like:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,19 +20,40 @@
   commonmark: require('./presets/commonmark')
 };
 
-
-var BAD_PROTOCOLS    = [ 'vbscript', 'javascript', 'file' ];
+////////////////////////////////////////////////////////////////////////////////
+//
+// This validator does not pretent to functionality of full weight sanitizers.
+// It's a tradeoff between default security, simplicity and usability.
+// If you need different setup - override validator method as you wish. Or
+// replace it with dummy function and use external sanitizer.
+//
+
+var BAD_PROTOCOLS      = [ 'vbscript', 'javascript', 'file', 'data' ];
+var ALLOWED_DATA_MIMES = [
+  'data:image/gif',
+  'data:image/png',
+  'data:image/jpeg',
+  'data:image/webp'
+];
 
 function validateLink(url) {
   // url should be normalized at this point, and existing entities are decoded
-  //
-  var str = url.trim().toLowerCase();
-
-  if (str.indexOf(':') >= 0 && BAD_PROTOCOLS.indexOf(str.split(':')[0]) >= 0) {
+
+  var str      = url.trim().toLowerCase(),
+      protocol = str.split(':')[0];
+
+  if (str.indexOf(':') >= 0 && BAD_PROTOCOLS.indexOf(protocol) >= 0) {
+    if (protocol === 'data' && ALLOWED_DATA_MIMES.indexOf(str.split(';')[0]) >= 0) {
+      return true;
+    }
     return false;
   }
+
   return true;
 }
+
+////////////////////////////////////////////////////////////////////////////////
+
 
 var RECODE_HOSTNAME_FOR = [ 'http:', 'https:', 'mailto:' ];
 
```
