# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in javascript
**Pair ID:** 631_3
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `631_3`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```javascript
Lines 1-27 of the vulnerable file.

'use strict'

const BB = require('bluebird')

const stat = BB.promisify(require('graceful-fs').stat)
const gentlyRm = BB.promisify(require('../../utils/gently-rm.js'))
const correctMkdir = BB.promisify(require('../../utils/correct-mkdir'))
const moduleStagingPath = require('../module-staging-path.js')
const move = require('../../utils/move.js')
const npa = require('npm-package-arg')
const npm = require('../../npm.js')
const packageId = require('../../utils/package-id.js')
let pacoteOpts
const path = require('path')
const localWorker = require('./extract-worker.js')
const workerFarm = require('worker-farm')
const isRegistry = require('../../utils/is-registry.js')

const WORKER_PATH = require.resolve('./extract-worker.js')
let workers

// NOTE: temporarily disabled on non-OSX due to ongoing issues:
//
// * Seems to make Windows antivirus issues much more common
// * Messes with Docker (I think)
//
// There are other issues that should be fixed that affect OSX too:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,7 @@
 
 const stat = BB.promisify(require('graceful-fs').stat)
 const gentlyRm = BB.promisify(require('../../utils/gently-rm.js'))
-const correctMkdir = BB.promisify(require('../../utils/correct-mkdir'))
+const mkdirp = BB.promisify(require('mkdirp'))
 const moduleStagingPath = require('../module-staging-path.js')
 const move = require('../../utils/move.js')
 const npa = require('npm-package-arg')
@@ -127,7 +127,7 @@
 function finishModule (bundler, child, stageTo, stageFrom) {
   // If we were the one's who bundled this module…
   if (child.fromBundle === bundler) {
-    return correctMkdir(path.dirname(stageTo)).then(() => {
+    return mkdirp(path.dirname(stageTo)).then(() => {
       return move(stageFrom, stageTo)
     })
   } else {
```
