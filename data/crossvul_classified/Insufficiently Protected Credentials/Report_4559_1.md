# CrossVul Fix Pair: Insufficiently Protected Credentials in javascript
**Pair ID:** 4559_1
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4559_1`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```javascript
Lines 9-49 of the vulnerable file.

    var errObj;

    if (!err && !data) {
      return cb(error.buildResponse('generic_error', 'Something went wrong'));
    }

    if (!err && data.err) {
      err = data.err;
      data = null;
    }

    if (!err && data.error) {
      err = data;
      data = null;
    }

    if (err) {
      errObj = {
        original: err
      };

      if (err.response && err.response.statusCode) {
        errObj.statusCode = err.response.statusCode;
      }

      if (err.response && err.response.statusText) {
        errObj.statusText = err.response.statusText;
      }

      if (err.response && err.response.body) {
        err = err.response.body;
      }

      if (err.err) {
        err = err.err;
      }

      errObj.code =
        err.code || err.error || err.error_code || err.status || null;

      errObj.description =
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,6 +26,12 @@
       errObj = {
         original: err
       };
+
+      objectHelper.updatePropertyOn(
+        errObj,
+        'original.response.req._data.password',
+        '*****'
+      );
 
       if (err.response && err.response.statusCode) {
         errObj.statusCode = err.response.statusCode;
```
