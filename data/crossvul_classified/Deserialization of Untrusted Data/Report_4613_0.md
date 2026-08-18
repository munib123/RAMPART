# CrossVul Fix Pair: Deserialization of Untrusted Data in javascript
**Pair ID:** 4613_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4613_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```javascript
Lines 1-29 of the vulnerable file.

/*
Copyright (c) 2014, Yahoo! Inc. All rights reserved.
Copyrights licensed under the New BSD License.
See the accompanying LICENSE file for terms.
*/

'use strict';

// Generate an internal UID to make the regexp pattern harder to guess.
var UID                 = Math.floor(Math.random() * 0x10000000000).toString(16);
var PLACE_HOLDER_REGEXP = new RegExp('"@__(F|R|D|M|S|U|I)-' + UID + '-(\\d+)__@"', 'g');

var IS_NATIVE_CODE_REGEXP = /\{\s*\[native code\]\s*\}/g;
var IS_PURE_FUNCTION = /function.*?\(/;
var IS_ARROW_FUNCTION = /.*?=>.*?/;
var UNSAFE_CHARS_REGEXP   = /[<>\/\u2028\u2029]/g;

var RESERVED_SYMBOLS = ['*', 'async'];

// Mapping of unsafe HTML and invalid JavaScript line terminator chars to their
// Unicode char counterparts which are safe to use in JavaScript strings.
var ESCAPED_CHARS = {
    '<'     : '\\u003C',
    '>'     : '\\u003E',
    '/'     : '\\u002F',
    '\u2028': '\\u2028',
    '\u2029': '\\u2029'
};

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,9 +6,12 @@
 
 'use strict';
 
+var randomBytes = require('randombytes');
+
 // Generate an internal UID to make the regexp pattern harder to guess.
-var UID                 = Math.floor(Math.random() * 0x10000000000).toString(16);
-var PLACE_HOLDER_REGEXP = new RegExp('"@__(F|R|D|M|S|U|I)-' + UID + '-(\\d+)__@"', 'g');
+var UID_LENGTH          = 16;
+var UID                 = generateUID();
+var PLACE_HOLDER_REGEXP = new RegExp('(\\\\)?"@__(F|R|D|M|S|U|I)-' + UID + '-(\\d+)__@"', 'g');
 
 var IS_NATIVE_CODE_REGEXP = /\{\s*\[native code\]\s*\}/g;
 var IS_PURE_FUNCTION = /function.*?\(/;
@@ -31,6 +34,15 @@
     return ESCAPED_CHARS[unsafeChar];
 }
 
+function generateUID() {
+    var bytes = randomBytes(UID_LENGTH);
+    var result = '';
+    for(var i=0; i<UID_LENGTH; ++i) {
+        result += bytes[i].toString(16);
+    }
+    return result;
+}
+
 function deleteFunctions(obj){
     var functionKeys = [];
     for (var key in obj) {
@@ -187,7 +199,14 @@
     // Replaces all occurrences of function, regexp, date, map and set placeholders in the
     // JSON string with their string representations. If the original value can
     // not be found, then `undefined` is used.
-    return str.replace(PLACE_HOLDER_REGEXP, function (match, type, valueIndex) {
+    return str.replace(PLACE_HOLDER_REGEXP, function (match, backSlash, type, valueIndex) {
+        // The placeholder may not be preceded by a backslash. This is to prevent
+        // replacing things like `"a\"@__R-<UID>-0__@"` and thus outputting
+        // invalid JS.
+        if (backSlash) {
+            return match;
+        }
+
         if (type === 'D') {
             return "new Date(\"" + dates[valueIndex].toISOString() + "\")";
         }
```
