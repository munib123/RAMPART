# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 865_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `865_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 97-132 of the vulnerable file.

        if (buffer.length >= length + 4) {
          var result = internalEval(buffer.toString('utf8', 4, length + 4));
          var tmpBuffer = new Buffer(buffer.length - 4 - length);
          buffer.copy(tmpBuffer, 0, length + 4, buffer.length);
          buffer = tmpBuffer;
          state = 'start';
          sendResponse(result);
        } else {
          return;
        }
      }
    }
  });

  readable.on('end', function() {
    state = 'eof';
    DEBUG && console.error("-- Session ended");
  });
}

if (process.argv.indexOf('--pipe') != -1) {
  rnUbuntuServer(process.stdin, process.stdout);
} else {
  var port = process.env['REACT_SERVER_PORT'] || 5000;
  process.argv.forEach((val, index) => {
    if (val == '--port') {
      port = process.argv[++index];
    }
  });


  var server = net.createServer((sock) => {
    DEBUG && console.error("-- Connection from RN client");
    rnUbuntuServer(sock, sock);
  }).listen(port, function() { console.error("-- Server starting") });
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -114,6 +114,18 @@
   });
 }
 
+var closeDangerousConnection = function(sock) {
+  var remoteAddress = sock.remoteAddress;
+  if(remoteAddress.indexOf("127.0.0.1") == -1) {
+    console.log("WARN: connection not from localhost, will be closed: ", remoteAddress);
+    sock.destroy();
+    return true;
+  } else {
+    console.log("Connection from: ", remoteAddress);
+    return false;
+  }
+}
+
 if (process.argv.indexOf('--pipe') != -1) {
   rnUbuntuServer(process.stdin, process.stdout);
 } else {
@@ -127,6 +139,7 @@
 
   var server = net.createServer((sock) => {
     DEBUG && console.error("-- Connection from RN client");
-    rnUbuntuServer(sock, sock);
+    if(!closeDangerousConnection(sock))
+      rnUbuntuServer(sock, sock);
   }).listen(port, function() { console.error("-- Server starting") });
 }
```
