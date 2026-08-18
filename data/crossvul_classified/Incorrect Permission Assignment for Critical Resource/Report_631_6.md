# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in javascript
**Pair ID:** 631_6
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `631_6`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```javascript
Lines 1-26 of the vulnerable file.

'use strict'
var path = require('path')
var fs = require('graceful-fs')
var rimraf = require('rimraf')
var asyncMap = require('slide').asyncMap
var correctMkdir = require('../../utils/correct-mkdir')
var npm = require('../../npm.js')
var andIgnoreErrors = require('../and-ignore-errors.js')
var move = require('../../utils/move.js')
var isInside = require('path-is-inside')
var vacuum = require('fs-vacuum')

// This is weird because we want to remove the module but not it's node_modules folder
// allowing for this allows us to not worry about the order of operations
module.exports = function (staging, pkg, log, next) {
  log.silly('remove', pkg.path)
  if (pkg.target) {
    removeLink(pkg, next)
  } else {
    removeDir(pkg, log, next)
  }
}

function removeLink (pkg, next) {
  var base = isInside(pkg.path, npm.prefix) ? npm.prefix : pkg.path
  rimraf(pkg.path, (err) => {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,7 +3,7 @@
 var fs = require('graceful-fs')
 var rimraf = require('rimraf')
 var asyncMap = require('slide').asyncMap
-var correctMkdir = require('../../utils/correct-mkdir')
+var mkdirp = require('mkdirp')
 var npm = require('../../npm.js')
 var andIgnoreErrors = require('../and-ignore-errors.js')
 var move = require('../../utils/move.js')
@@ -52,7 +52,7 @@
   function makeTarget (readdirEr, files) {
     if (readdirEr) return cleanup()
     if (!files.length) return cleanup()
-    correctMkdir(path.join(pkg.path, 'node_modules'), function (mkdirEr) { moveModules(mkdirEr, files) })
+    mkdirp(path.join(pkg.path, 'node_modules'), function (mkdirEr) { moveModules(mkdirEr, files) })
   }
 
   function moveModules (mkdirEr, files) {
```
