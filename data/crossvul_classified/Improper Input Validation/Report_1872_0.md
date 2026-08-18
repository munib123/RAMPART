# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 1872_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1872_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 65-106 of the vulnerable file.

                else if (response.settings.varyEtag) {
                    const etagBase = response.headers.etag.slice(0, -1);
                    if (etag === etagBase + '-gzip"' ||
                        etag === etagBase + '-deflate"') {

                        response.code(304);
                        break;
                    }
                }
            }
        }
        else {
            const ifModifiedSinceHeader = request.headers['if-modified-since'];
            const lastModifiedHeader = response.headers['last-modified'];

            if (ifModifiedSinceHeader &&
                lastModifiedHeader) {

                // Weak verifier

                const ifModifiedSince = Date.parse(ifModifiedSinceHeader);
                const lastModified = Date.parse(lastModifiedHeader);

                if (ifModifiedSince &&
                    lastModified &&
                    ifModifiedSince >= lastModified) {

                    response.code(304);
                }
            }
        }
    }

    internals.state(response, (err) => {

        if (err) {
            request._log(['state', 'response', 'error'], err);
            request._states = {};                                           // Clear broken state
            return next(err);
        }

        internals.cache(response);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,8 +82,8 @@
 
                 // Weak verifier
 
-                const ifModifiedSince = Date.parse(ifModifiedSinceHeader);
-                const lastModified = Date.parse(lastModifiedHeader);
+                const ifModifiedSince = internals.parseDate(ifModifiedSinceHeader);
+                const lastModified = internals.parseDate(lastModifiedHeader);
 
                 if (ifModifiedSince &&
                     lastModified &&
@@ -144,6 +144,15 @@
             return Auth.response(request, next);               // Must be last in case requires access to headers
         });
     });
+};
+
+
+internals.parseDate = function (string) {
+
+    try {
+        return Date.parse(string);
+    }
+    catch (errIgnore) { }
 };
 
 
```
