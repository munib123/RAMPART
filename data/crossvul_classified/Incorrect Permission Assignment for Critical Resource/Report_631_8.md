# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in javascript
**Pair ID:** 631_8
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `631_8`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```javascript
Lines 1-29 of the vulnerable file.

var chownr = require('chownr')
var dezalgo = require('dezalgo')
var fs = require('graceful-fs')
var inflight = require('inflight')
var log = require('npmlog')
var mkdirp = require('mkdirp')

// memoize the directories created by this step
var effectiveOwner
module.exports = function correctMkdir (path, cb) {
  cb = dezalgo(cb)
  cb = inflight('correctMkdir:' + path, cb)
  if (!cb) {
    return log.silly('correctMkdir', path, 'correctMkdir already in flight; waiting')
  } else {
    log.silly('correctMkdir', path, 'correctMkdir not in flight; initializing')
  }
  var stats = {}

  if (stats[path]) return cb(null, stats[path])

  fs.stat(path, function (er, st) {
    if (er) return makeDirectory(path, stats, cb)

    if (!st.isDirectory()) {
      log.error('correctMkdir', 'invalid dir %s', path)
      return cb(er)
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,21 +6,21 @@
 var mkdirp = require('mkdirp')
 
 // memoize the directories created by this step
+var stats = {}
 var effectiveOwner
 module.exports = function correctMkdir (path, cb) {
   cb = dezalgo(cb)
   cb = inflight('correctMkdir:' + path, cb)
   if (!cb) {
-    return log.silly('correctMkdir', path, 'correctMkdir already in flight; waiting')
+    return log.verbose('correctMkdir', path, 'correctMkdir already in flight; waiting')
   } else {
-    log.silly('correctMkdir', path, 'correctMkdir not in flight; initializing')
+    log.verbose('correctMkdir', path, 'correctMkdir not in flight; initializing')
   }
-  var stats = {}
 
   if (stats[path]) return cb(null, stats[path])
 
   fs.stat(path, function (er, st) {
-    if (er) return makeDirectory(path, stats, cb)
+    if (er) return makeDirectory(path, cb)
 
     if (!st.isDirectory()) {
       log.error('correctMkdir', 'invalid dir %s', path)
@@ -60,12 +60,12 @@
   return effectiveOwner
 }
 
-function makeDirectory (path, stats, cb) {
+function makeDirectory (path, cb) {
   cb = inflight('makeDirectory:' + path, cb)
   if (!cb) {
-    return log.silly('makeDirectory', path, 'creation already in flight; waiting')
+    return log.verbose('makeDirectory', path, 'creation already in flight; waiting')
   } else {
-    log.silly('makeDirectory', path, 'creation not in flight; initializing')
+    log.verbose('makeDirectory', path, 'creation not in flight; initializing')
   }
 
   var owner = calculateOwner()
```
