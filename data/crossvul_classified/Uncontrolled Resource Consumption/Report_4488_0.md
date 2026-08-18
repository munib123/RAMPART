# CrossVul Fix Pair: Uncontrolled Resource Consumption in javascript
**Pair ID:** 4488_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4488_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```javascript
Lines 269-313 of the vulnerable file.

 * Decode a packet String (JSON data)
 *
 * @param {String} str
 * @return {Object} packet
 * @api private
 */

function decodeString(str) {
  var i = 0;
  // look up type
  var p = {
    type: Number(str.charAt(0))
  };

  if (null == exports.types[p.type]) {
    return error('unknown packet type ' + p.type);
  }

  // look up attachments if type binary
  if (exports.BINARY_EVENT === p.type || exports.BINARY_ACK === p.type) {
    var buf = '';
    while (str.charAt(++i) !== '-') {
      buf += str.charAt(i);
      if (i == str.length) break;
    }
    if (buf != Number(buf) || str.charAt(i) !== '-') {
      throw new Error('Illegal attachments');
    }
    p.attachments = Number(buf);
  }

  // look up namespace (if any)
  if ('/' === str.charAt(i + 1)) {
    p.nsp = '';
    while (++i) {
      var c = str.charAt(i);
      if (',' === c) break;
      p.nsp += c;
      if (i === str.length) break;
    }
  } else {
    p.nsp = '/';
  }

  // look up id
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -286,11 +286,9 @@
 
   // look up attachments if type binary
   if (exports.BINARY_EVENT === p.type || exports.BINARY_ACK === p.type) {
-    var buf = '';
-    while (str.charAt(++i) !== '-') {
-      buf += str.charAt(i);
-      if (i == str.length) break;
-    }
+    var start = i + 1;
+    while (str.charAt(++i) !== '-' && i != str.length) {}
+    var buf = str.substring(start, i);
     if (buf != Number(buf) || str.charAt(i) !== '-') {
       throw new Error('Illegal attachments');
     }
@@ -299,13 +297,13 @@
 
   // look up namespace (if any)
   if ('/' === str.charAt(i + 1)) {
-    p.nsp = '';
+    var start = i + 1;
     while (++i) {
       var c = str.charAt(i);
       if (',' === c) break;
-      p.nsp += c;
       if (i === str.length) break;
     }
+    p.nsp = str.substring(start, i);
   } else {
     p.nsp = '/';
   }
@@ -313,17 +311,16 @@
   // look up id
   var next = str.charAt(i + 1);
   if ('' !== next && Number(next) == next) {
-    p.id = '';
+    var start = i + 1;
     while (++i) {
       var c = str.charAt(i);
       if (null == c || Number(c) != c) {
         --i;
         break;
       }
-      p.id += str.charAt(i);
       if (i === str.length) break;
     }
-    p.id = Number(p.id);
+    p.id = Number(str.substring(start, i + 1));
   }
 
   // look up json data
```
