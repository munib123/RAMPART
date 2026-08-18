# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in javascript
**Pair ID:** 631_5
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `631_5`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```javascript
Lines 1-27 of the vulnerable file.

'use strict'
var fs = require('graceful-fs')
var path = require('path')
var chain = require('slide').chain
var iferr = require('iferr')
var rimraf = require('rimraf')
var correctMkdir = require('../../utils/correct-mkdir')
var rmStuff = require('../../unbuild.js').rmStuff
var lifecycle = require('../../utils/lifecycle.js')
var move = require('../../utils/move.js')

/*
  Move a module from one point in the node_modules tree to another.
  Do not disturb either the source or target location's node_modules
  folders.
*/

module.exports = function (staging, pkg, log, next) {
  log.silly('move', pkg.fromPath, pkg.path)
  chain([
    [lifecycle, pkg.package, 'preuninstall', pkg.fromPath, { failOk: true }],
    [lifecycle, pkg.package, 'uninstall', pkg.fromPath, { failOk: true }],
    [rmStuff, pkg.package, pkg.fromPath],
    [lifecycle, pkg.package, 'postuninstall', pkg.fromPath, { failOk: true }],
    [moveModuleOnly, pkg.fromPath, pkg.path, log],
    [lifecycle, pkg.package, 'preinstall', pkg.path, { failOk: true }],
    [removeEmptyParents, path.resolve(pkg.fromPath, '..')]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,7 @@
 var chain = require('slide').chain
 var iferr = require('iferr')
 var rimraf = require('rimraf')
-var correctMkdir = require('../../utils/correct-mkdir')
+var mkdirp = require('mkdirp')
 var rmStuff = require('../../unbuild.js').rmStuff
 var lifecycle = require('../../utils/lifecycle.js')
 var move = require('../../utils/move.js')
@@ -67,7 +67,7 @@
   function makeDestination (next) {
     return function () {
       log.silly('move', 'make sure destination parent exists', path.resolve(to, '..'))
-      correctMkdir(path.resolve(to, '..'), iferr(done, moveNodeModules(next)))
+      mkdirp(path.resolve(to, '..'), iferr(done, moveNodeModules(next)))
     }
   }
 
@@ -87,7 +87,7 @@
 
   function moveNodeModulesBack (next) {
     return function () {
-      correctMkdir(from, iferr(done, function () {
+      mkdirp(from, iferr(done, function () {
         log.silly('move', 'put source node_modules back', fromModules)
         move(tempFromModules, fromModules).then(next, done)
       }))
```
