# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 553_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `553_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 52-92 of the vulnerable file.

}

Glance.prototype.stop = function Glance$stop () {
  if (this.server) {
    this.server.close()
  }
}

Glance.prototype.serveRequest = function Glance$serveRequest (req, res) {
  var request = {}
  var self = this

  request.fullPath = path.join(
    self.dir,
    decodeURIComponent(parse(req.url).pathname)
  )

  request.ip = req.socket.remoteAddress
  request.method = req.method.toLowerCase()
  request.response = res

  if (request.method !== 'get') {
    return self.emit('error', 405, request, res)
  }

  if (self.nodot && /^\./.test(path.basename(request.fullPath))) {
    return self.emit('error', 404, request, res)
  }

  fs.stat(request.fullPath, statFile)

  function statFile (err, stat) {
    if (err) {
      return self.emit('error', 404, request, res)
    }

    if (!stat.isDirectory()) {
      self.emit('read', request)

      return filed(request.fullPath).pipe(res)
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -69,6 +69,11 @@
   request.ip = req.socket.remoteAddress
   request.method = req.method.toLowerCase()
   request.response = res
+
+  // prevent traversing directories that are parents of the root
+  if (request.fullPath.slice(0, self.dir.length) !== self.dir) {
+    return self.emit('error', 403, request, res)
+  }
 
   if (request.method !== 'get') {
     return self.emit('error', 405, request, res)
```
