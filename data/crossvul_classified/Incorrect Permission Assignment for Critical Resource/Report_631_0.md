# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in javascript
**Pair ID:** 631_0
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `631_0`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```javascript
Lines 1-31 of the vulnerable file.

var CC = require('config-chain').ConfigChain
var inherits = require('inherits')
var configDefs = require('./defaults.js')
var types = configDefs.types
var once = require('once')
var fs = require('fs')
var path = require('path')
var nopt = require('nopt')
var ini = require('ini')
var Umask = configDefs.Umask
var correctMkdir = require('../utils/correct-mkdir.js')
var umask = require('../utils/umask')
var isWindows = require('../utils/is-windows.js')

exports.load = load
exports.Conf = Conf
exports.loaded = false
exports.rootConf = null
exports.usingBuiltin = false
exports.defs = configDefs

Object.defineProperty(exports, 'defaults', { get: function () {
  return configDefs.defaults
}, enumerable: true })

Object.defineProperty(exports, 'types', { get: function () {
  return configDefs.types
}, enumerable: true })

exports.validate = validate

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,7 +8,7 @@
 var nopt = require('nopt')
 var ini = require('ini')
 var Umask = configDefs.Umask
-var correctMkdir = require('../utils/correct-mkdir.js')
+var mkdirp = require('mkdirp')
 var umask = require('../utils/umask')
 var isWindows = require('../utils/is-windows.js')
 
@@ -153,7 +153,7 @@
     // annoying humans and their expectations!
     if (conf.get('prefix')) {
       var etc = path.resolve(conf.get('prefix'), 'etc')
-      correctMkdir(etc, function () {
+      mkdirp(etc, function () {
         defaults.globalconfig = path.resolve(etc, 'npmrc')
         defaults.globalignorefile = path.resolve(etc, 'npmignore')
         afterUserContinuation()
@@ -235,7 +235,7 @@
     this.loadUid(function (er) {
       if (er) return cb(er)
       // Without prefix, nothing will ever work
-      correctMkdir(this.prefix, cb)
+      mkdirp(this.prefix, cb)
     }.bind(this))
   }.bind(this))
 }
@@ -292,7 +292,7 @@
       done(null)
     })
   } else {
-    correctMkdir(path.dirname(target.path), function (er) {
+    mkdirp(path.dirname(target.path), function (er) {
       if (er) return then(er)
       fs.writeFile(target.path, data, 'utf8', function (er) {
         if (er) return then(er)
```
