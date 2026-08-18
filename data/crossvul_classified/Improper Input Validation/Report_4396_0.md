# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4396_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4396_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 595-635 of the vulnerable file.

      pos++;
      string = '/' + string;
    }

    if (parts.preventInvalidHostname) {
      URI.ensureValidHostname(parts.hostname, parts.protocol);
    }

    if (parts.port) {
      URI.ensureValidPort(parts.port);
    }

    return string.substring(pos) || '/';
  };
  URI.parseAuthority = function(string, parts) {
    string = URI.parseUserinfo(string, parts);
    return URI.parseHost(string, parts);
  };
  URI.parseUserinfo = function(string, parts) {
    // extract username:password
    var firstBackSlash = string.indexOf('\\');
    var firstSlash = string.indexOf('/');
    var slash = firstBackSlash === -1 ? firstSlash : (firstSlash !== -1 ? Math.min(firstBackSlash, firstSlash): firstSlash)
    var pos = string.lastIndexOf('@', firstSlash > -1 ? firstSlash : string.length - 1);
    var t;

    // authority@ must come before /path or \path
    if (pos > -1 && (slash === -1 || pos < slash)) {
      t = string.substring(0, pos).split(':');
      parts.username = t[0] ? URI.decode(t[0]) : null;
      t.shift();
      parts.password = t[0] ? URI.decode(t.join(':')) : null;
      string = string.substring(pos + 1);
    } else {
      parts.username = null;
      parts.password = null;
    }

    return string;
  };
  URI.parseQuery = function(string, escapeQuerySpace) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -612,19 +612,22 @@
   };
   URI.parseUserinfo = function(string, parts) {
     // extract username:password
+    var _string = string
     var firstBackSlash = string.indexOf('\\');
+    if (firstBackSlash !== -1) {
+      string = string.replace(/\\/g, '/')
+    }
     var firstSlash = string.indexOf('/');
-    var slash = firstBackSlash === -1 ? firstSlash : (firstSlash !== -1 ? Math.min(firstBackSlash, firstSlash): firstSlash)
     var pos = string.lastIndexOf('@', firstSlash > -1 ? firstSlash : string.length - 1);
     var t;
 
     // authority@ must come before /path or \path
-    if (pos > -1 && (slash === -1 || pos < slash)) {
+    if (pos > -1 && (firstSlash === -1 || pos < firstSlash)) {
       t = string.substring(0, pos).split(':');
       parts.username = t[0] ? URI.decode(t[0]) : null;
       t.shift();
       parts.password = t[0] ? URI.decode(t.join(':')) : null;
-      string = string.substring(pos + 1);
+      string = _string.substring(pos + 1);
     } else {
       parts.username = null;
       parts.password = null;
```
