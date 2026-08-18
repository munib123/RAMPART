# CrossVul Fix Pair: Insertion of Sensitive Information into Log File in javascript
**Pair ID:** 4087_2
**Vulnerability Class:** Insertion of Sensitive Information into Log File
**CWE:** CWE-532
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4087_2`)

## Vulnerability Information & PoC

## Description
Insertion of Sensitive Information into Log File - While logging all information may be helpful during development stages, it is important that logging levels be set appropriately before a product ships so that sensitive user data and system inform...

## Vulnerable Code
```javascript
Lines 1-35 of the vulnerable file.


module.exports = errorHandler
module.exports.exit = exit

var cbCalled = false
var log = require('npmlog')
var npm = require('../npm.js')
var itWorked = false
var path = require('path')
var wroteLogFile = false
var exitCode = 0
var rollbacks = npm.rollbacks
var chain = require('slide').chain
var errorMessage = require('./error-message.js')
var stopMetrics = require('./metrics.js').stop

const cacheFile = require('./cache-file.js')

var logFileName
function getLogFile () {
  if (!logFileName) {
    logFileName = path.resolve(npm.config.get('cache'), '_logs', (new Date()).toISOString().replace(/[.:]/g, '_') + '-debug.log')
  }
  return logFileName
}

var timings = {
  version: npm.version,
  command: process.argv.slice(2),
  logfile: null
}
process.on('timing', function (name, value) {
  if (timings[name]) { timings[name] += value } else { timings[name] = value }
})

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,6 +12,7 @@
 var rollbacks = npm.rollbacks
 var chain = require('slide').chain
 var errorMessage = require('./error-message.js')
+var replaceInfo = require('./replace-info.js')
 var stopMetrics = require('./metrics.js').stop
 
 const cacheFile = require('./cache-file.js')
@@ -175,14 +176,16 @@
   ].forEach(function (k) {
     var v = er[k]
     if (!v) return
+    v = replaceInfo(v)
     log.verbose(k, v)
   })
 
   log.verbose('cwd', process.cwd())
 
   var os = require('os')
+  var args = replaceInfo(process.argv)
   log.verbose('', os.type() + ' ' + os.release())
-  log.verbose('argv', process.argv.map(JSON.stringify).join(' '))
+  log.verbose('argv', args.map(JSON.stringify).join(' '))
   log.verbose('node', process.version)
   log.verbose('npm ', 'v' + npm.version)
 
```
