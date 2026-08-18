# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in javascript
**Pair ID:** 4503_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4503_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```javascript
Lines 1-28 of the vulnerable file.

var create     = require('./create')
var ssbKeys    = require('ssb-keys')
var path       = require('path')
var osenv      = require('osenv')
var mkdirp     = require('mkdirp')
var rimraf     = require('rimraf')
var valid      = require('./lib/validators')
var pkg        = require('./package.json')
const pull = require('pull-stream')
const pullNotify = require('pull-notify')
const pullCat = require('pull-cat')

function isString(s) { return 'string' === typeof s }
function isObject(o) { return 'object' === typeof o }
function isFunction (f) { return 'function' === typeof f }

var manifest = {
  get: 'async',
  createFeedStream: 'source',
  createLogStream: 'source',
  messagesByType: 'source',
  createHistoryStream: 'source',
  createUserStream: 'source',
  createWriteStream: 'sink',
  createSequenceStream: 'source',
  links: 'source',
  add: 'async',
  publish: 'async',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,7 +5,9 @@
 var mkdirp     = require('mkdirp')
 var rimraf     = require('rimraf')
 var valid      = require('./lib/validators')
-var pkg        = require('./package.json')
+var version    = require('./package.json').version
+var help       = require('./help')
+
 const pull = require('pull-stream')
 const pullNotify = require('pull-notify')
 const pullCat = require('pull-cat')
@@ -35,7 +37,7 @@
   status: 'sync',
   getVectorClock: 'async',
   version: 'sync',
-  help: 'sync',
+  help: 'sync'
 }
 
 module.exports = {
@@ -106,40 +108,21 @@
     ssb.since(sequenceNotifier)
 
     return self = {
+      keys                     : opts.keys,
       id                       : feed.id,
-      keys                     : opts.keys,
 
-      ready                    : function () {
-        return ssb.ready.value
+      whoami                   : () => {
+        return { id: feed.id }
       },
-
-      progress                 : function () {
-        return ssb.progress
-      },
-
-      status                   : function () {
+      version                  : () => version,
+      ready                    : () => ssb.ready.value,
+      progress                 : () => ssb.progress,
+      status                   : () => {
         return {
-          progress: self.progress(),
+          progress: ssb.progress,
           db: ssb.status,
           sync: since()
         }
-      },
-
-      version                  : function () {
-        return pkg.version
-      },
-
-      createSequenceStream: () => {
-        // If the initial value is `undefined` we want it to be `-1`.
-        // This is because `-1` is a magic sequence number for an empty log.
-        const initialValue = ssb.since.value !== undefined
-          ? ssb.since.value
-          : -1
-        
-        return pullCat([
-          pull.values([initialValue]),
-          sequenceNotifier.listen()
-        ])
       },
 
       //temporary!
@@ -164,20 +147,31 @@
       getLatest                : valid.async(ssb.getLatest, 'feedId'),
       latestSequence           : valid.async(ssb.latestSequence, 'feedId'),
       createFeed               : ssb.createFeed,
-      whoami                   : function () { return { id: feed.id } },
       createFeedStream         : valid.source(ssb.createFeedStream, 'readStreamOpts?'),
       createHistoryStream      : valid.source(ssb.createHistoryStream, ['createHistoryStreamOpts'], ['feedId', 'number?', 'boolean?']),
       createLogStream          : valid.source(ssb.createLogStream, 'readStreamOpts?'),
       createUserStream         : valid.source(ssb.createUserStream, 'createUserStreamOpts'),
+      createSequenceStream     : () => {
+        // If the initial value is `undefined` we want it to be `-1`.
+        // This is because `-1` is a magic sequence number for an empty log.
+        const initialValue = ssb.since.value !== undefined
+          ? ssb.since.value
+          : -1
+
+        return pullCat([
+          pull.values([initialValue]),
+          sequenceNotifier.listen()
+        ])
+      },
       links                    : valid.source(ssb.links, 'linksOpts'),
-      sublevel                 : ssb.sublevel,
+      // sublevel                 : ssb.sublevel, // Disabled as does not appear to be used
       messagesByType           : valid.source(ssb.messagesByType, 'string|messagesByTypeOpts'),
       createWriteStream        : ssb.createWriteStream,
       getVectorClock           : ssb.getVectorClock,
       getAtSequence            : ssb.getAtSequence,
       addBoxer                 : ssb.addBoxer,
       addUnboxer               : ssb.addUnboxer,
-      help                     : function () { return require('./help') }
+      help                     : () => help
     }
   }
 }
```
