# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 778_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `778_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 1-36 of the vulnerable file.

/*jshint laxbreak:true */

var sizeParser = require('filesize-parser');
var exec = require('child_process').exec, child;

module.exports = function(path, opts, cb) {
  if (!cb) {
    cb = opts;
    opts = {};
  }

  var cmd = module.exports.cmd(path, opts);
  opts.timeout = opts.timeout || 5000;

  exec(cmd, opts, function(e, stdout, stderr) {
    if (e) { return cb(e); }
    if (stderr) { return cb(new Error(stderr)); }

    return cb(null, module.exports.parse(path, stdout, opts));
  });
};

module.exports.cmd = function(path, opts) {
  opts = opts || {};
  var format = [
    'name=',
    'size=%[size]',
    'format=%m',
    'colorspace=%[colorspace]',
    'height=%[height]',
    'width=%[width]',
    'orientation=%[orientation]',
    (opts.exif ? '%[exif:*]' : '')
  ].join("\n");

  return 'identify -format "' + format + '" ' + path;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,15 +9,18 @@
     opts = {};
   }
 
-  var cmd = module.exports.cmd(path, opts);
-  opts.timeout = opts.timeout || 5000;
-
-  exec(cmd, opts, function(e, stdout, stderr) {
-    if (e) { return cb(e); }
+  if(/;|&|`|\$|\(|\)|\|\||\||!|>|<|\?|\${/g.test(JSON.stringify(path))) {
+    console.log('Input Validation failed, Suspicious Characters found');
+  } else {
+    var cmd = module.exports.cmd(path, opts);
+    opts.timeout = opts.timeout || 5000;
+    exec(cmd, opts, function(e, stdout, stderr) {
+      if (e) { return cb(e); }
     if (stderr) { return cb(new Error(stderr)); }
 
-    return cb(null, module.exports.parse(path, stdout, opts));
+      return cb(null, module.exports.parse(path, stdout, opts));
   });
+}
 };
 
 module.exports.cmd = function(path, opts) {
```
