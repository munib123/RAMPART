# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 1693_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1693_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 159-199 of the vulnerable file.

    acceptableMethods = Object.keys(acceptableMethods);

    // send a friendly error response
    throw new errors.MethodNotAllowedError(
      method + ' method not allowed. Please consider ' +
      acceptableMethods.join(', ').replace(/,\s(\w+)$/," or $1") +
      ' instead.');
  };

  this.handleNotFound = function (reqUrl, params, reqObj, respObj) {
    throw new errors.NotFoundError(reqUrl + ' not found.');
  };

  this.handleNoMatchedRoute = function (method, reqUrl, params, reqObj, respObj) {
    var staticPath
      , controllerInst
      , nonMethodRoutes;


    // Get the path to the file, decoding the request URI
    staticPath = this.config.staticFilePath + decodeURIComponent(reqUrl);
    // Ignore querystring
    staticPath = staticPath.split('?')[0];

    // Static?
    if (utils.file.existsSync(staticPath)) {
      this.handleStaticFile(staticPath, params, reqUrl, reqObj, respObj, params);
    }
    else {
      nonMethodRoutes = this.router.all(reqUrl);

      // Good route, wrong verb -- 405?
      if (nonMethodRoutes.length) {
        this.handleMethodNotAllowed(method, reqUrl, params, reqObj, respObj,
          nonMethodRoutes);
      }
      // Nada, 404
      else {
        this.handleNotFound(reqUrl, params, reqObj, respObj);
      }
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -176,7 +176,14 @@
 
 
     // Get the path to the file, decoding the request URI
-    staticPath = this.config.staticFilePath + decodeURIComponent(reqUrl);
+    staticPath = path.resolve(path.join(this.config.staticFilePath, decodeURIComponent(reqUrl)));
+
+    // Prevent directory traversal
+    if (staticPath.indexOf(this.config.staticFilePath) !== 0) {
+      this.handleNotFound(reqUrl, params, reqObj, respObj);
+      return;
+    }
+
     // Ignore querystring
     staticPath = staticPath.split('?')[0];
 
```
