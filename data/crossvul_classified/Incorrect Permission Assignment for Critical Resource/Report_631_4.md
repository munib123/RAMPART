# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in javascript
**Pair ID:** 631_4
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `631_4`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```javascript
Lines 1-26 of the vulnerable file.

'use strict'
const path = require('path')
const fs = require('graceful-fs')
const Bluebird = require('bluebird')
const rimraf = Bluebird.promisify(require('rimraf'))
const lstat = Bluebird.promisify(fs.lstat)
const readdir = Bluebird.promisify(fs.readdir)
const symlink = Bluebird.promisify(fs.symlink)
const gentlyRm = Bluebird.promisify(require('../../utils/gently-rm'))
const moduleStagingPath = require('../module-staging-path.js')
const move = require('move-concurrently')
const moveOpts = {fs: fs, Promise: Bluebird, maxConcurrency: 4}
const getRequested = require('../get-requested.js')
const log = require('npmlog')
const packageId = require('../../utils/package-id.js')
const correctMkdir = Bluebird.promisify(require('../../utils/correct-mkdir.js'))

module.exports = function (staging, pkg, log) {
  log.silly('finalize', pkg.realpath)

  const extractedTo = moduleStagingPath(staging, pkg)

  const delpath = path.join(path.dirname(pkg.realpath), '.' + path.basename(pkg.realpath) + '.DELETE')
  let movedDestAway = false

  const requested = pkg.package._requested || getRequested(pkg)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,6 +3,7 @@
 const fs = require('graceful-fs')
 const Bluebird = require('bluebird')
 const rimraf = Bluebird.promisify(require('rimraf'))
+const mkdirp = Bluebird.promisify(require('mkdirp'))
 const lstat = Bluebird.promisify(fs.lstat)
 const readdir = Bluebird.promisify(fs.readdir)
 const symlink = Bluebird.promisify(fs.symlink)
@@ -13,7 +14,6 @@
 const getRequested = require('../get-requested.js')
 const log = require('npmlog')
 const packageId = require('../../utils/package-id.js')
-const correctMkdir = Bluebird.promisify(require('../../utils/correct-mkdir.js'))
 
 module.exports = function (staging, pkg, log) {
   log.silly('finalize', pkg.realpath)
@@ -48,7 +48,7 @@
   }
 
   function makeParentPath (dir) {
-    return correctMkdir(path.dirname(dir))
+    return mkdirp(path.dirname(dir))
   }
 
   function moveStagingToDestination () {
@@ -81,7 +81,7 @@
     if (!movedDestAway) return
     return readdir(path.join(delpath, 'node_modules')).catch(() => []).then((modules) => {
       if (!modules.length) return
-      return correctMkdir(path.join(pkg.realpath, 'node_modules')).then(() => Bluebird.map(modules, (file) => {
+      return mkdirp(path.join(pkg.realpath, 'node_modules')).then(() => Bluebird.map(modules, (file) => {
         const from = path.join(delpath, 'node_modules', file)
         const to = path.join(pkg.realpath, 'node_modules', file)
         return move(from, to, moveOpts)
```
