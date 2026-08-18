# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in javascript
**Pair ID:** 4391_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4391_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```javascript
Lines 1-20 of the vulnerable file.

'use strict'
const URL = require('url').URL
const path = require('path')

const config = require('../../config')
const logger = require('../../logger')

exports.uploadImage = function (imagePath, callback) {
  if (!callback || typeof callback !== 'function') {
    logger.error('Callback has to be a function')
    return
  }

  if (!imagePath || typeof imagePath !== 'string') {
    callback(new Error('Image path is missing or wrong'), null)
    return
  }

  callback(null, (new URL(path.basename(imagePath), config.serverURL + '/uploads/')).href)
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,7 @@
 'use strict'
 const URL = require('url').URL
 const path = require('path')
+const fs = require('fs')
 
 const config = require('../../config')
 const logger = require('../../logger')
@@ -16,5 +17,13 @@
     return
   }
 
-  callback(null, (new URL(path.basename(imagePath), config.serverURL + '/uploads/')).href)
+  const fileName = path.basename(imagePath)
+  // move image from temporary path to upload directory
+  try {
+    fs.copyFileSync(imagePath, path.join(config.uploadsPath, fileName))
+  } catch (e) {
+    callback(new Error('Error while moving file'), null)
+    return
+  }
+  callback(null, (new URL(fileName, config.serverURL + '/uploads/')).href)
 }
```
