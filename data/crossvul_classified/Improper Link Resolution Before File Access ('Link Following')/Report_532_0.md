# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in javascript
**Pair ID:** 532_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `532_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```javascript
Lines 1-35 of the vulnerable file.

'use strict'

const assert = require('assert')
const EE = require('events').EventEmitter
const Parser = require('./parse.js')
const fs = require('fs')
const fsm = require('fs-minipass')
const path = require('path')
const mkdir = require('./mkdir.js')
const mkdirSync = mkdir.sync
const wc = require('./winchars.js')

const ONENTRY = Symbol('onEntry')
const CHECKFS = Symbol('checkFs')
const MAKEFS = Symbol('makeFs')
const FILE = Symbol('file')
const DIRECTORY = Symbol('directory')
const LINK = Symbol('link')
const SYMLINK = Symbol('symlink')
const HARDLINK = Symbol('hardlink')
const UNSUPPORTED = Symbol('unsupported')
const UNKNOWN = Symbol('unknown')
const CHECKPATH = Symbol('checkPath')
const MKDIR = Symbol('mkdir')
const ONERROR = Symbol('onError')
const PENDING = Symbol('pending')
const PEND = Symbol('pend')
const UNPEND = Symbol('unpend')
const ENDED = Symbol('ended')
const MAYBECLOSE = Symbol('maybeClose')
const SKIP = Symbol('skip')
const DOCHOWN = Symbol('doChown')
const UID = Symbol('uid')
const GID = Symbol('gid')

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,6 +12,7 @@
 
 const ONENTRY = Symbol('onEntry')
 const CHECKFS = Symbol('checkFs')
+const ISREUSABLE = Symbol('isReusable')
 const MAKEFS = Symbol('makeFs')
 const FILE = Symbol('file')
 const DIRECTORY = Symbol('directory')
@@ -351,6 +352,17 @@
     entry.resume()
   }
 
+  // Check if we can reuse an existing filesystem entry safely and
+  // overwrite it, rather than unlinking and recreating
+  // Windows doesn't report a useful nlink, so we just never reuse entries
+  [ISREUSABLE] (entry, st) {
+    return entry.type === 'File' &&
+      !this.unlink &&
+      st.isFile() &&
+      st.nlink <= 1 &&
+      process.platform !== 'win32'
+  }
+
   // check if a thing is there, and if so, try to clobber it
   [CHECKFS] (entry) {
     this[PEND]()
@@ -360,7 +372,7 @@
       fs.lstat(entry.absolute, (er, st) => {
         if (st && (this.keep || this.newer && st.mtime > entry.mtime))
           this[SKIP](entry)
-        else if (er || (entry.type === 'File' && !this.unlink && st.isFile()))
+        else if (er || this[ISREUSABLE](entry, st))
           this[MAKEFS](null, entry)
         else if (st.isDirectory()) {
           if (entry.type === 'Directory') {
@@ -422,7 +434,7 @@
       const st = fs.lstatSync(entry.absolute)
       if (this.keep || this.newer && st.mtime > entry.mtime)
         return this[SKIP](entry)
-      else if (entry.type === 'File' && !this.unlink && st.isFile())
+      else if (this[ISREUSABLE](entry, st))
         return this[MAKEFS](null, entry)
       else {
         try {
```
