# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in javascript
**Pair ID:** 4641_1
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4641_1`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```javascript
Lines 34-74 of the vulnerable file.

  opts = opts || {}

  if (opts.defaultRoute) {
    assert(typeof opts.defaultRoute === 'function', 'The default route must be a function')
    this.defaultRoute = opts.defaultRoute
  } else {
    this.defaultRoute = null
  }

  if (opts.onBadUrl) {
    assert(typeof opts.onBadUrl === 'function', 'The bad url handler must be a function')
    this.onBadUrl = opts.onBadUrl
  } else {
    this.onBadUrl = null
  }

  this.caseSensitive = opts.caseSensitive === undefined ? true : opts.caseSensitive
  this.ignoreTrailingSlash = opts.ignoreTrailingSlash || false
  this.maxParamLength = opts.maxParamLength || 100
  this.allowUnsafeRegex = opts.allowUnsafeRegex || false
  this.versioning = opts.versioning || acceptVersionStrategy
  this.trees = {}
  this.routes = []
}

Router.prototype.on = function on (method, path, opts, handler, store) {
  if (typeof opts === 'function') {
    if (handler !== undefined) {
      store = handler
    }
    handler = opts
    opts = {}
  }
  // path validation
  assert(typeof path === 'string', 'Path should be a string')
  assert(path.length > 0, 'The path could not be empty')
  assert(path[0] === '/' || path[0] === '*', 'The first character of a path should be `/` or `*`')
  // handler validation
  assert(typeof handler === 'function', 'Handler should be a function')

  this._on(method, path, opts, handler, store)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,7 +51,7 @@
   this.ignoreTrailingSlash = opts.ignoreTrailingSlash || false
   this.maxParamLength = opts.maxParamLength || 100
   this.allowUnsafeRegex = opts.allowUnsafeRegex || false
-  this.versioning = opts.versioning || acceptVersionStrategy
+  this.versioning = opts.versioning || acceptVersionStrategy(false)
   this.trees = {}
   this.routes = []
 }
@@ -111,6 +111,9 @@
   })
 
   const version = opts.version
+  if (version != null && this.versioning.disabled) {
+    this.versioning = acceptVersionStrategy(true)
+  }
 
   for (var i = 0, len = path.length; i < len; i++) {
     // search for parametric or wildcard routes
```
