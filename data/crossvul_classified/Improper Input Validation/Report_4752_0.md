# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4752_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4752_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 50-92 of the vulnerable file.

// note that it excludes \x3B ";"
var COOKIE_OCTET  = /[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]/;
var COOKIE_OCTETS = new RegExp('^'+COOKIE_OCTET.source+'+$');

var CONTROL_CHARS = /[\x00-\x1F]/;

// Double quotes are part of the value (see: S4.1.1).
// '\r', '\n' and '\0' should be treated as a terminator in the "relaxed" mode
// (see: https://github.com/ChromiumWebApps/chromium/blob/b3d3b4da8bb94c1b2e061600df106d590fda3620/net/cookies/parsed_cookie.cc#L60)
// '=' and ';' are attribute/values separators
// (see: https://github.com/ChromiumWebApps/chromium/blob/b3d3b4da8bb94c1b2e061600df106d590fda3620/net/cookies/parsed_cookie.cc#L64)
var COOKIE_PAIR = /^(([^=;]+))\s*=\s*([^\n\r\0]*)/;

// Used to parse non-RFC-compliant cookies like '=abc' when given the `loose`
// option in Cookie.parse:
var LOOSE_COOKIE_PAIR = /^((?:=)?([^=;]*)\s*=\s*)?([^\n\r\0]*)/;

// RFC6265 S4.1.1 defines path value as 'any CHAR except CTLs or ";"'
// Note ';' is \x3B
var PATH_VALUE = /[\x20-\x3A\x3C-\x7E]+/;

// Used for checking whether or not there is a trailing semi-colon
var TRAILING_SEMICOLON = /;+$/;

var DAY_OF_MONTH = /^(\d{1,2})[^\d]*$/;
var TIME = /^(\d{1,2})[^\d]*:(\d{1,2})[^\d]*:(\d{1,2})[^\d]*$/;
var MONTH = /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/i;

var MONTH_TO_NUM = {
  jan:0, feb:1, mar:2, apr:3, may:4, jun:5,
  jul:6, aug:7, sep:8, oct:9, nov:10, dec:11
};
var NUM_TO_MONTH = [
  'Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'
];
var NUM_TO_DAY = [
  'Sun','Mon','Tue','Wed','Thu','Fri','Sat'
];

var YEAR = /^(\d{2}|\d{4})$/; // 2 to 4 digits

var MAX_TIME = 2147483647000; // 31-bit max
var MIN_TIME = 0; // 31-bit min
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -68,9 +68,6 @@
 // Note ';' is \x3B
 var PATH_VALUE = /[\x20-\x3A\x3C-\x7E]+/;
 
-// Used for checking whether or not there is a trailing semi-colon
-var TRAILING_SEMICOLON = /;+$/;
-
 var DAY_OF_MONTH = /^(\d{1,2})[^\d]*$/;
 var TIME = /^(\d{1,2})[^\d]*:(\d{1,2})[^\d]*:(\d{1,2})[^\d]*$/;
 var MONTH = /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/i;
@@ -327,12 +324,6 @@
   }
   str = str.trim();
 
-  // S4.1.1 Trailing semi-colons are not part of the specification.
-  var semiColonCheck = TRAILING_SEMICOLON.exec(str);
-  if (semiColonCheck) {
-    str = str.slice(0, semiColonCheck.index);
-  }
-
   // We use a regex to parse the "name-value-pair" part of S5.2
   var firstSemi = str.indexOf(';'); // S5.2 step 1
   var pairRe = options.loose ? LOOSE_COOKIE_PAIR : COOKIE_PAIR;
@@ -362,7 +353,7 @@
   // S5.2.3 "unparsed-attributes consist of the remainder of the set-cookie-string
   // (including the %x3B (";") in question)." plus later on in the same section
   // "discard the first ";" and trim".
-  var unparsed = str.slice(firstSemi).replace(/^\s*;\s*/,'').trim();
+  var unparsed = str.slice(firstSemi + 1).trim();
 
   // "If the unparsed-attributes string is empty, skip the rest of these
   // steps."
@@ -378,9 +369,12 @@
    * cookie-attribute-list".  Therefore, in this implementation, we overwrite
    * the previous value.
    */
-  var cookie_avs = unparsed.split(/\s*;\s*/);
+  var cookie_avs = unparsed.split(';');
   while (cookie_avs.length) {
-    var av = cookie_avs.shift();
+    var av = cookie_avs.shift().trim();
+    if (av.length === 0) { // happens if ";;" appears
+      continue;
+    }
     var av_sep = av.indexOf('=');
     var av_key, av_value;
 
```
