# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in javascript
**Pair ID:** 631_2
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `631_2`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```javascript
Lines 85-125 of the vulnerable file.

      })
    })
  }

  // FIXME: there used to be registry completion here, but it stopped making
  // sense somewhere around 50,000 packages on the registry
  cb()
}

// system packages
var fs = require('fs')
var path = require('path')

// dependencies
var log = require('npmlog')
var readPackageTree = require('read-package-tree')
var readPackageJson = require('read-package-json')
var chain = require('slide').chain
var asyncMap = require('slide').asyncMap
var archy = require('archy')
var correctMkdir = require('./utils/correct-mkdir.js')
var rimraf = require('rimraf')
var iferr = require('iferr')
var validate = require('aproba')
var uniq = require('lodash.uniq')
var Bluebird = require('bluebird')

// npm internal utils
var npm = require('./npm.js')
var locker = require('./utils/locker.js')
var lock = locker.lock
var unlock = locker.unlock
var parseJSON = require('./utils/parse-json.js')
var output = require('./utils/output.js')
var saveMetrics = require('./utils/metrics.js').save

// install specific libraries
var copyTree = require('./install/copy-tree.js')
var readShrinkwrap = require('./install/read-shrinkwrap.js')
var computeMetadata = require('./install/deps.js').computeMetadata
var prefetchDeps = require('./install/deps.js').prefetchDeps
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -102,7 +102,7 @@
 var chain = require('slide').chain
 var asyncMap = require('slide').asyncMap
 var archy = require('archy')
-var correctMkdir = require('./utils/correct-mkdir.js')
+var mkdirp = require('mkdirp')
 var rimraf = require('rimraf')
 var iferr = require('iferr')
 var validate = require('aproba')
@@ -648,7 +648,7 @@
   log.silly('install', 'readGlobalPackageData')
   var self = this
   this.loadArgMetadata(iferr(cb, function () {
-    correctMkdir(self.where, iferr(cb, function () {
+    mkdirp(self.where, iferr(cb, function () {
       var pkgs = {}
       self.args.forEach(function (pkg) {
         pkgs[pkg.name] = true
@@ -665,7 +665,7 @@
   validate('F', arguments)
   log.silly('install', 'readLocalPackageData')
   var self = this
-  correctMkdir(this.where, iferr(cb, function () {
+  mkdirp(this.where, iferr(cb, function () {
     readPackageTree(self.where, iferr(cb, function (currentTree) {
       self.currentTree = currentTree
       self.currentTree.warnings = []
```
