# CrossVul Fix Pair: Insertion of Sensitive Information into Log File in javascript
**Pair ID:** 4087_1
**Vulnerability Class:** Insertion of Sensitive Information into Log File
**CWE:** CWE-532
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4087_1`)

## Vulnerability Information & PoC

## Description
Insertion of Sensitive Information into Log File - While logging all information may be helpful during development stages, it is important that logging levels be set appropriately before a product ships so that sensitive user data and system inform...

## Vulnerable Code
```javascript
Lines 1-26 of the vulnerable file.

'use strict'

const deprCheck = require('./utils/depr-check')
const path = require('path')
const log = require('npmlog')
const readPackageTree = require('read-package-tree')
const rimraf = require('rimraf')
const validate = require('aproba')
const npa = require('npm-package-arg')
const npm = require('./npm')
let npmConfig
const npmlog = require('npmlog')
const limit = require('call-limit')
const tempFilename = require('./utils/temp-filename')
const pacote = require('pacote')
const isWindows = require('./utils/is-windows.js')

function andLogAndFinish (spec, tracker, done) {
  validate('SOF|SZF|OOF|OZF', [spec, tracker, done])
  return (er, pkg) => {
    if (er) {
      log.silly('fetchPackageMetaData', 'error for ' + String(spec), er.message)
      if (tracker) tracker.finish()
    }
    return done(er, pkg)
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,6 +3,7 @@
 const deprCheck = require('./utils/depr-check')
 const path = require('path')
 const log = require('npmlog')
+const pacote = require('pacote')
 const readPackageTree = require('read-package-tree')
 const rimraf = require('rimraf')
 const validate = require('aproba')
@@ -11,15 +12,17 @@
 let npmConfig
 const npmlog = require('npmlog')
 const limit = require('call-limit')
-const tempFilename = require('./utils/temp-filename')
-const pacote = require('pacote')
+const tempFilename = require('./utils/temp-filename.js')
+const replaceInfo = require('./utils/replace-info.js')
 const isWindows = require('./utils/is-windows.js')
 
 function andLogAndFinish (spec, tracker, done) {
   validate('SOF|SZF|OOF|OZF', [spec, tracker, done])
   return (er, pkg) => {
     if (er) {
-      log.silly('fetchPackageMetaData', 'error for ' + String(spec), er.message)
+      er.message = replaceInfo(er.message)
+      var spc = replaceInfo(String(spec))
+      log.silly('fetchPackageMetaData', 'error for ' + spc, er.message)
       if (tracker) tracker.finish()
     }
     return done(er, pkg)
```
