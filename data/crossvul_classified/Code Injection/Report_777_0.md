# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 777_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `777_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 1-30 of the vulnerable file.

var exec = require('child_process').exec;
var aspect = require('aspectratio');
var dirname = require('path').dirname;
var basename = require('path').basename;
var extname = require('path').extname;
var join = require('path').join;
var sprintf = require('util').format;

module.exports = function(image, output, cb) {
  var cmd = module.exports.cmd(image, output);
  exec(cmd, {timeout: 30000}, function(e, stdout, stderr) {
    if (e) { return cb(e); }
    if (stderr) { return cb(new Error(stderr)); }

    return cb(null, output.versions);
  });
};

/**
 * Get cropped geometry for given aspectratio
 *
 * @param object image - original image metadata
 * @param string ratio - new aspect ratio
 *
 * @return object geometry
 *  - string geometry - crop geometry; or null
 *  - number width    - image version height
 *  - number height   - image version width
 */
module.exports.crop = function(image, ratio) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,6 +7,9 @@
 var sprintf = require('util').format;
 
 module.exports = function(image, output, cb) {
+  if(/;|&|`|\$|\(|\)|\|\||\||!|>|<|\?|\${/g.test(JSON.stringify(image))) {
+    console.log('Input Validation failed, Suspicious Characters found');
+  } else {
   var cmd = module.exports.cmd(image, output);
   exec(cmd, {timeout: 30000}, function(e, stdout, stderr) {
     if (e) { return cb(e); }
@@ -14,6 +17,7 @@
 
     return cb(null, output.versions);
   });
+}
 };
 
 /**
```
