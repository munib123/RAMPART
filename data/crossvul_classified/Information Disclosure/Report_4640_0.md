# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in javascript
**Pair ID:** 4640_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4640_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```javascript
Lines 2-48 of the vulnerable file.


page.viewportSize = {
    width: body.viewportSize.width || 600,
    height: body.viewportSize.height || 600
};

page.settings.javascriptEnabled = body.settings.javascriptEnabled !== false;
page.settings.resourceTimeout = body.settings.resourceTimeout || 10000;


if(body.cookies.length > 0) {
    for(var i in body.cookies) {
        page.addCookie(body.cookies[i]);
    }
}

page.onResourceRequested = function (request, networkRequest) {
    console.log('Request ' + request.url);
    if (request.url.lastIndexOf(body.url, 0) === 0) {
        return;
    }

    //potentially dangerous request
    if (request.url.lastIndexOf("file:///", 0) === 0 && !body.allowLocalFilesAccess) {
        networkRequest.abort();
        return;
    }

    //to support cdn like format //cdn.jquery...
    if (request.url.lastIndexOf("file://", 0) === 0 && request.url.lastIndexOf("file:///", 0) !== 0) {
        networkRequest.changeUrl(request.url.replace("file://", "http://"));
    }

    if (body.waitForJS && request.url.lastIndexOf("http://intruct-javascript-ending", 0) === 0) {
        pageJSisDone = true;
    }
};

page.onConsoleMessage = function(msg, line, source) {
    console.log(msg, line, source);
};

page.onResourceError = function(resourceError) {
    console.warn('Unable to load resource (#' + resourceError.id + 'URL:' + resourceError.url + ')');
    console.warn('Error code: ' + resourceError.errorCode + '. Description: ' + resourceError.errorString);
};

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,17 +19,17 @@
     console.log('Request ' + request.url);
     if (request.url.lastIndexOf(body.url, 0) === 0) {
         return;
-    }
-
-    //potentially dangerous request
-    if (request.url.lastIndexOf("file:///", 0) === 0 && !body.allowLocalFilesAccess) {
-        networkRequest.abort();
-        return;
-    }
+    }   
 
     //to support cdn like format //cdn.jquery...
     if (request.url.lastIndexOf("file://", 0) === 0 && request.url.lastIndexOf("file:///", 0) !== 0) {
         networkRequest.changeUrl(request.url.replace("file://", "http://"));
+    }
+
+     //potentially dangerous request
+     if (request.url.lastIndexOf("http://", 0) !== 0 && request.url.lastIndexOf("https://", 0) && !body.allowLocalFilesAccess) {
+        networkRequest.abort();
+        return;
     }
 
     if (body.waitForJS && request.url.lastIndexOf("http://intruct-javascript-ending", 0) === 0) {
```
