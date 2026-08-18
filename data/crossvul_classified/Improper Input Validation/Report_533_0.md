# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 533_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `533_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 244-284 of the vulnerable file.


    var stat = function (err) {
      if (err) return next(err)
      utimes(name, header, function (err) {
        if (err) return next(err)
        if (win32) return next()
        chperm(name, header, next)
      })
    }

    var onsymlink = function () {
      if (win32) return next() // skip symlinks on win for now before it can be tested
      xfs.unlink(name, function () {
        xfs.symlink(header.linkname, name, stat)
      })
    }

    var onlink = function () {
      if (win32) return next() // skip links on win for now before it can be tested
      xfs.unlink(name, function () {
        var srcpath = path.resolve(cwd, header.linkname)

        xfs.link(srcpath, name, function (err) {
          if (err && err.code === 'EPERM' && opts.hardlinkAsFilesFallback) {
            stream = xfs.createReadStream(srcpath)
            return onfile()
          }

          stat(err)
        })
      })
    }

    var onfile = function () {
      var ws = xfs.createWriteStream(name)
      var rs = mapStream(stream, header)

      ws.on('error', function (err) { // always forward errors on destroy
        rs.destroy(err)
      })

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -261,7 +261,7 @@
     var onlink = function () {
       if (win32) return next() // skip links on win for now before it can be tested
       xfs.unlink(name, function () {
-        var srcpath = path.resolve(cwd, header.linkname)
+        var srcpath = path.join(cwd, path.join('/', header.linkname))
 
         xfs.link(srcpath, name, function (err) {
           if (err && err.code === 'EPERM' && opts.hardlinkAsFilesFallback) {
```
