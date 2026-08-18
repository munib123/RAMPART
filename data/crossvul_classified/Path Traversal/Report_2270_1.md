# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 2270_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2270_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 395-435 of the vulnerable file.


SendStream.prototype.pipe = function(res){
  var self = this
    , args = arguments
    , root = this._root;

  // references
  this.res = res;

  // decode the path
  var path = utils.decode(this.path)
  if (path === -1) return this.error(400)

  // null byte(s)
  if (~path.indexOf('\0')) return this.error(400);

  var parts
  if (root !== null) {
    // join / normalize from optional root dir
    path = normalize(join(root, path))
    root = normalize(root)

    // malicious path
    if (path.substr(0, root.length) !== root) {
      debug('malicious path "%s"', path)
      return this.error(403)
    }

    // explode path parts
    parts = path.substr(root.length + 1).split(sep)
  } else {
    // ".." is malicious without "root"
    if (upPathRegexp.test(path)) {
      debug('malicious path "%s"', path)
      return this.error(403)
    }

    // explode path parts
    parts = normalize(path).split(sep)

    // resolve the path
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -412,7 +412,7 @@
   if (root !== null) {
     // join / normalize from optional root dir
     path = normalize(join(root, path))
-    root = normalize(root)
+    root = normalize(root + sep)
 
     // malicious path
     if (path.substr(0, root.length) !== root) {
@@ -421,7 +421,7 @@
     }
 
     // explode path parts
-    parts = path.substr(root.length + 1).split(sep)
+    parts = path.substr(root.length).split(sep)
   } else {
     // ".." is malicious without "root"
     if (upPathRegexp.test(path)) {
```
