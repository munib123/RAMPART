# CrossVul Fix Pair: Resource Management Errors in javascript
**Pair ID:** 4955_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4955_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```javascript
Lines 293-333 of the vulnerable file.


    let header = 'Hawk mac="' + mac + '"' +
                 (artifacts.hash ? ', hash="' + artifacts.hash + '"' : '');

    if (artifacts.ext !== null &&
        artifacts.ext !== undefined &&
        artifacts.ext !== '') {                       // Other falsey values allowed

        header = header + ', ext="' + Hoek.escapeHeaderAttribute(artifacts.ext) + '"';
    }

    return header;
};


/*
 * Arguments and options are the same as authenticate() with the exception that the only supported options are:
 * 'hostHeaderName', 'localtimeOffsetMsec', 'host', 'port'
 */

exports.authenticateBewit = function (req, credentialsFunc, options, callback) {

    callback = Hoek.nextTick(callback);

    // Application time

    const now = Utils.now(options.localtimeOffsetMsec);

    // Convert node Http request object to a request configuration object

    const request = Utils.parseRequest(req, options);
    if (request instanceof Error) {
        return callback(Boom.badRequest(request.message));
    }

    // Extract bewit

    //                                 1     2             3           4
    const resource = request.url.match(/^(\/.*)([\?&])bewit\=([^&$]*)(?:&(.+))?$/);
    if (!resource) {
        return callback(Utils.unauthorized());
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -310,6 +310,11 @@
  * 'hostHeaderName', 'localtimeOffsetMsec', 'host', 'port'
  */
 
+
+//                       1     2             3           4
+internals.bewitRegex = /^(\/.*)([\?&])bewit\=([^&$]*)(?:&(.+))?$/;
+
+
 exports.authenticateBewit = function (req, credentialsFunc, options, callback) {
 
     callback = Hoek.nextTick(callback);
@@ -327,8 +332,11 @@
 
     // Extract bewit
 
-    //                                 1     2             3           4
-    const resource = request.url.match(/^(\/.*)([\?&])bewit\=([^&$]*)(?:&(.+))?$/);
+    if (request.url.length > Utils.limits.maxMatchLength) {
+        return callback(Boom.badRequest('Resource path exceeds max length'));
+    }
+
+    const resource = request.url.match(internals.bewitRegex);
     if (!resource) {
         return callback(Utils.unauthorized());
     }
```
