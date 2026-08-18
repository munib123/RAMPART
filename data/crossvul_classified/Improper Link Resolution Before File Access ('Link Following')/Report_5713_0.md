# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in javascript
**Pair ID:** 5713_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5713_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```javascript
Lines 460-500 of the vulnerable file.


Object.defineProperty(npm, "globalDir",
  { get : function () {
      return (process.platform !== "win32")
           ? path.resolve(npm.globalPrefix, "lib", "node_modules")
           : path.resolve(npm.globalPrefix, "node_modules")
    }
  , enumerable : true
  })

Object.defineProperty(npm, "root",
  { get : function () { return npm.dir } })

Object.defineProperty(npm, "cache",
  { get : function () { return npm.config.get("cache") }
  , set : function (r) { return npm.config.set("cache", r) }
  , enumerable : true
  })

var tmpFolder
Object.defineProperty(npm, "tmp",
  { get : function () {
      if (!tmpFolder) tmpFolder = "npm-" + process.pid
      return path.resolve(npm.config.get("tmp"), tmpFolder)
    }
  , enumerable : true
  })

// the better to repl you with
Object.getOwnPropertyNames(npm.commands).forEach(function (n) {
  if (npm.hasOwnProperty(n) || n === "config") return

  Object.defineProperty(npm, n, { get: function () {
    return function () {
      var args = Array.prototype.slice.call(arguments, 0)
        , cb = defaultCb

      if (args.length === 1 && Array.isArray(args[0])) {
        args = args[0]
      }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -477,9 +477,14 @@
   })
 
 var tmpFolder
+var crypto = require("crypto")
+var rand = crypto.randomBytes(6)
+                 .toString("base64")
+                 .replace(/\//g, '_')
+                 .replace(/\+/, '-')
 Object.defineProperty(npm, "tmp",
   { get : function () {
-      if (!tmpFolder) tmpFolder = "npm-" + process.pid
+      if (!tmpFolder) tmpFolder = "npm-" + process.pid + "-" + rand
       return path.resolve(npm.config.get("tmp"), tmpFolder)
     }
   , enumerable : true
```
