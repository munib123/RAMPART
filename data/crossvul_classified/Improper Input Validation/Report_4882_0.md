# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4882_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4882_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 35-75 of the vulnerable file.

  if (defaultExt && /^\./.test(defaultExt)) defaultExt = defaultExt.replace(/^\./, '');

  // Support hashes and .types files in mimeTypes @since 0.8
  if (opts.mimeTypes) {
    try {
      // You can pass a JSON blob here---useful for CLI use
      opts.mimeTypes = JSON.parse(opts.mimeTypes);
    } catch (e) {}
    if (typeof opts.mimeTypes === 'string') {
      mime.load(opts.mimeTypes);
    }
    else if (typeof opts.mimeTypes === 'object') {
      mime.define(opts.mimeTypes);
    }
  }


  return function middleware (req, res, next) {

    // Strip any null bytes from the url
    while(req.url.indexOf('%00') !== -1) {
      req.url = req.url.replace(/\%00/g, '');
    }
    // Figure out the path for the file from the given url
    var parsed = url.parse(req.url);
    try {
      decodeURIComponent(req.url); // check validity of url
      var pathname = decodePathname(parsed.pathname);
    }
    catch (err) {
      return status[400](res, next, { error: err });
    }

    var file = path.normalize(
          path.join(root,
            path.relative(
              path.join('/', baseDir),
              pathname
            )
          )
        ),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,9 +52,21 @@
   return function middleware (req, res, next) {
 
     // Strip any null bytes from the url
+    // This was at one point necessary because of an old bug in url.parse
+    //
+    // See: https://github.com/jfhbrook/node-ecstatic/issues/16#issuecomment-3039914
+    // See: https://github.com/jfhbrook/node-ecstatic/commit/43f7e72a31524f88f47e367c3cc3af710e67c9f4
+    //
+    // But this opens up a regex dos attack vector! D:
+    //
+    // Based on some research (ie asking #node-dev if this is still an issue),
+    // it's *probably* not an issue. :)
+    /*
     while(req.url.indexOf('%00') !== -1) {
       req.url = req.url.replace(/\%00/g, '');
     }
+    */
+
     // Figure out the path for the file from the given url
     var parsed = url.parse(req.url);
     try {
```
