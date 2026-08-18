# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 617_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `617_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 507-547 of the vulnerable file.

      else
      {
        return cc;
      }
    });
  }
};

var globalExceptionHandler = undefined;
function setupGlobalExceptionHandler() {
  if (!globalExceptionHandler) {
    globalExceptionHandler = function test (msg, url, linenumber)
    {
      var errorId = randomString(20);
      var userAgent = padutils.escapeHtml(navigator.userAgent);
      if ($("#editorloadingbox").attr("display") != "none"){
        //show javascript errors to the user
        $("#editorloadingbox").css("padding", "10px");
        $("#editorloadingbox").css("padding-top", "45px");
        $("#editorloadingbox").html("<div style='text-align:left;color:red;font-size:16px;'><b>An error occurred</b><br>The error was reported with the following id: '" + errorId + "'<br><br><span style='color:black;font-weight:bold;font-size:16px'>Please press and hold Ctrl and press F5 to reload this page, if the problem persists please send this error message to your webmaster: </span><div style='color:black;font-size:14px'>'"
          + "ErrorId: " + errorId + "<br>URL: " + window.location.href + "<br>UserAgent: " + userAgent + "<br>" + msg + " in " + url + " at line " + linenumber + "'</div></div>");
      }

      //send javascript errors to the server
      var errObj = {errorInfo: JSON.stringify({errorId: errorId, msg: msg, url: window.location.href, linenumber: linenumber, userAgent: navigator.userAgent})};
      var loc = document.location;
      var url = loc.protocol + "//" + loc.hostname + ":" + loc.port + "/" + loc.pathname.substr(1, loc.pathname.indexOf("/p/")) + "jserror";
 
      $.post(url, errObj);
 
      return false;
    };
    window.onerror = globalExceptionHandler;
  }
}

padutils.setupGlobalExceptionHandler = setupGlobalExceptionHandler;

padutils.binarySearch = require('./ace2_common').binarySearch;

exports.randomString = randomString;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -524,7 +524,7 @@
         $("#editorloadingbox").css("padding", "10px");
         $("#editorloadingbox").css("padding-top", "45px");
         $("#editorloadingbox").html("<div style='text-align:left;color:red;font-size:16px;'><b>An error occurred</b><br>The error was reported with the following id: '" + errorId + "'<br><br><span style='color:black;font-weight:bold;font-size:16px'>Please press and hold Ctrl and press F5 to reload this page, if the problem persists please send this error message to your webmaster: </span><div style='color:black;font-size:14px'>'"
-          + "ErrorId: " + errorId + "<br>URL: " + window.location.href + "<br>UserAgent: " + userAgent + "<br>" + msg + " in " + url + " at line " + linenumber + "'</div></div>");
+          + "ErrorId: " + errorId + "<br>URL: " + padutils.escapeHtml(window.location.href) + "<br>UserAgent: " + userAgent + "<br>" + msg + " in " + url + " at line " + linenumber + "'</div></div>");
       }
 
       //send javascript errors to the server
```
