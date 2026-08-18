# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in javascript
**Pair ID:** 569_0
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `569_0`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```javascript
Lines 3-43 of the vulnerable file.

var required = require('requires-port')
  , qs = require('querystringify')
  , protocolre = /^([a-z][a-z0-9.+-]*:)?(\/\/)?([\S\s]*)/i
  , slashes = /^[A-Za-z][A-Za-z0-9+-.]*:\/\//;

/**
 * These are the parse rules for the URL parser, it informs the parser
 * about:
 *
 * 0. The char it Needs to parse, if it's a string it should be done using
 *    indexOf, RegExp using exec and NaN means set as current value.
 * 1. The property we should set when parsing this value.
 * 2. Indication if it's backwards or forward parsing, when set as number it's
 *    the value of extra chars that should be split off.
 * 3. Inherit from location if non existing in the parser.
 * 4. `toLowerCase` the resulting value.
 */
var rules = [
  ['#', 'hash'],                        // Extract from the back.
  ['?', 'query'],                       // Extract from the back.
  ['/', 'pathname'],                    // Extract from the back.
  ['@', 'auth', 1],                     // Extract from the front.
  [NaN, 'host', undefined, 1, 1],       // Set left over value.
  [/:(\d+)$/, 'port', undefined, 1],    // RegExp the back.
  [NaN, 'hostname', undefined, 1, 1]    // Set left over.
];

/**
 * These properties should not be copied or inherited from. This is only needed
 * for all non blob URL's as a blob URL does not include a hash, only the
 * origin.
 *
 * @type {Object}
 * @private
 */
var ignore = { hash: 1, query: 1 };

/**
 * The location object differs when your code is loaded through a normal page,
 * Worker or through a worker using a blob. And with the blobble begins the
 * trouble as the location object will contain the URL of the blob, not the
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,6 +20,9 @@
 var rules = [
   ['#', 'hash'],                        // Extract from the back.
   ['?', 'query'],                       // Extract from the back.
+  function sanitize(address) {          // Sanitize what is left of the address
+    return address.replace('\\', '/');
+  },
   ['/', 'pathname'],                    // Extract from the back.
   ['@', 'auth', 1],                     // Extract from the front.
   [NaN, 'host', undefined, 1, 1],       // Set left over value.
@@ -47,7 +50,7 @@
  *
  * @param {Object|String} loc Optional default location object.
  * @returns {Object} lolcation object.
- * @api public
+ * @public
  */
 function lolcation(loc) {
   var location = global && global.location || {};
@@ -89,7 +92,7 @@
  *
  * @param {String} address URL we want to extract from.
  * @return {ProtocolExtract} Extracted information.
- * @api private
+ * @private
  */
 function extractProtocol(address) {
   var match = protocolre.exec(address);
@@ -107,7 +110,7 @@
  * @param {String} relative Pathname of the relative URL.
  * @param {String} base Pathname of the base URL.
  * @return {String} Resolved pathname.
- * @api private
+ * @private
  */
 function resolve(relative, base) {
   var path = (base || '/').split('/').slice(0, -1).concat(relative.split('/'))
@@ -140,11 +143,14 @@
  * create an actual constructor as it's much more memory efficient and
  * faster and it pleases my OCD.
  *
+ * It is worth noting that we should not use `URL` as class name to prevent
+ * clashes with the global URL instance that got introduced in browsers.
+ *
  * @constructor
  * @param {String} address URL we want to parse.
  * @param {Object|String} location Location defaults for relative paths.
  * @param {Boolean|Function} parser Parser for the query string.
- * @api public
+ * @private
  */
 function Url(address, location, parser) {
   if (!(this instanceof Url)) {
@@ -190,10 +196,16 @@
   // When the authority component is absent the URL starts with a path
   // component.
   //
-  if (!extracted.slashes) instructions[2] = [/(.*)/, 'pathname'];
+  if (!extracted.slashes) instructions[3] = [/(.*)/, 'pathname'];
 
   for (; i < instructions.length; i++) {
     instruction = instructions[i];
+
+    if (typeof instruction === 'function') {
+      address = instruction(address);
+      continue;
+    }
+
     parse = instruction[0];
     key = instruction[1];
 
@@ -284,8 +296,8 @@
  *                               used to parse the query.
  *                               When setting the protocol, double slash will be
  *                               removed from the final url if it is true.
- * @returns {URL}
- * @api public
+ * @returns {URL} URL instance for chaining.
+ * @public
  */
 function set(part, value, fn) {
   var url = this;
@@ -370,8 +382,8 @@
  * Transform the properties back in to a valid and full URL string.
  *
  * @param {Function} stringify Optional query stringify function.
- * @returns {String}
- * @api public
+ * @returns {String} Compiled version of the URL.
+ * @public
  */
 function toString(stringify) {
   if (!stringify || 'function' !== typeof stringify) stringify = qs.stringify;
```
