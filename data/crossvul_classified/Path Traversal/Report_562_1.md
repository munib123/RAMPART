# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 562_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `562_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 1-36 of the vulnerable file.

/*!
 * resolve-path
 * Copyright(c) 2014 Jonathan Ong
 * Copyright(c) 2015 Douglas Christopher Wilson
 * MIT Licensed
 */

'use strict'

/**
 * Module dependencies.
 * @private
 */

var createError = require('http-errors')
var normalize = require('path').normalize
var pathIsAbsolute = require('path-is-absolute')
var resolve = require('path').resolve
var sep = require('path').sep

/**
 * Module exports.
 * @public
 */

module.exports = resolvePath

/**
 * Module variables.
 * @private
 */

var UP_PATH_REGEXP = /(?:^|[\\/])\.\.(?:[\\/]|$)/

/**
 * Resolve relative path against a root path
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,7 @@
  */
 
 var createError = require('http-errors')
+var join = require('path').join
 var normalize = require('path').normalize
 var pathIsAbsolute = require('path-is-absolute')
 var resolve = require('path').resolve
@@ -82,9 +83,6 @@
     throw createError(403)
   }
 
-  // resolve & normalize the root path
-  root = normalize(resolve(root) + sep)
-
-  // resolve the path
-  return resolve(root, path)
+  // join the relative path
+  return normalize(join(resolve(root), path))
 }
```
