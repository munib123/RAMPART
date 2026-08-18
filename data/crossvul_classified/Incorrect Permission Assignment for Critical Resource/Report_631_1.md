# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in javascript
**Pair ID:** 631_1
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `631_1`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```javascript
Lines 1-26 of the vulnerable file.

module.exports = setUser

var assert = require('assert')
var path = require('path')
var fs = require('fs')
var correctMkdir = require('../utils/correct-mkdir.js')

function setUser (cb) {
  var defaultConf = this.root
  assert(defaultConf !== Object.prototype)

  // If global, leave it as-is.
  // If not global, then set the user to the owner of the prefix folder.
  // Just set the default, so it can be overridden.
  if (this.get('global')) return cb()
  if (process.env.SUDO_UID) {
    defaultConf.user = +(process.env.SUDO_UID)
    return cb()
  }

  var prefix = path.resolve(this.get('prefix'))
  correctMkdir(prefix, function (er) {
    if (er) return cb(er)
    fs.stat(prefix, function (er, st) {
      defaultConf.user = st && st.uid
      return cb(er)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,7 +3,7 @@
 var assert = require('assert')
 var path = require('path')
 var fs = require('fs')
-var correctMkdir = require('../utils/correct-mkdir.js')
+var mkdirp = require('mkdirp')
 
 function setUser (cb) {
   var defaultConf = this.root
@@ -19,7 +19,7 @@
   }
 
   var prefix = path.resolve(this.get('prefix'))
-  correctMkdir(prefix, function (er) {
+  mkdirp(prefix, function (er) {
     if (er) return cb(er)
     fs.stat(prefix, function (er, st) {
       defaultConf.user = st && st.uid
```
