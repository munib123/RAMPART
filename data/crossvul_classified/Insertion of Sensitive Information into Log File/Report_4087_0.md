# CrossVul Fix Pair: Insertion of Sensitive Information into Log File in javascript
**Pair ID:** 4087_0
**Vulnerability Class:** Insertion of Sensitive Information into Log File
**CWE:** CWE-532
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4087_0`)

## Vulnerability Information & PoC

## Description
Insertion of Sensitive Information into Log File - While logging all information may be helpful during development stages, it is important that logging levels be set appropriately before a product ships so that sensitive user data and system inform...

## Vulnerable Code
```javascript
Lines 11-51 of the vulnerable file.

        "or type 'node npm <args>'."
    )
    WScript.quit(1)
    return
  }

  process.title = 'npm'

  var unsupported = require('../lib/utils/unsupported.js')
  unsupported.checkForBrokenNode()

  var log = require('npmlog')
  log.pause() // will be unpaused when config is loaded.
  log.info('it worked if it ends with', 'ok')

  unsupported.checkForUnsupportedNode()

  var npm = require('../lib/npm.js')
  var npmconf = require('../lib/config/core.js')
  var errorHandler = require('../lib/utils/error-handler.js')

  var configDefs = npmconf.defs
  var shorthands = configDefs.shorthands
  var types = configDefs.types
  var nopt = require('nopt')

  // if npm is called as "npmg" or "npm_g", then
  // run in global mode.
  if (process.argv[1][process.argv[1].length - 1] === 'g') {
    process.argv.splice(1, 1, 'npm', '-g')
  }

  log.verbose('cli', process.argv)

  var conf = nopt(types, shorthands)
  npm.argv = conf.argv.remain
  if (npm.deref(npm.argv[0])) npm.command = npm.argv.shift()
  else conf.usage = true

  if (conf.version) {
    console.log(npm.version)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,7 @@
   var npm = require('../lib/npm.js')
   var npmconf = require('../lib/config/core.js')
   var errorHandler = require('../lib/utils/error-handler.js')
+  var replaceInfo = require('../lib/utils/replace-info.js')
 
   var configDefs = npmconf.defs
   var shorthands = configDefs.shorthands
@@ -40,7 +41,8 @@
     process.argv.splice(1, 1, 'npm', '-g')
   }
 
-  log.verbose('cli', process.argv)
+  var args = replaceInfo(process.argv)
+  log.verbose('cli', args)
 
   var conf = nopt(types, shorthands)
   npm.argv = conf.argv.remain
```
