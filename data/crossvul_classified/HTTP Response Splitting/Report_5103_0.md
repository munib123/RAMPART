# CrossVul Fix Pair: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting') in javascript
**Pair ID:** 5103_0
**Vulnerability Class:** HTTP Response Splitting
**CWE:** CWE-113
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5103_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting') - HTTP agents or components may include a web server, load balancer, reverse proxy, web caching proxy, application firewall, web browser, etc.

## Vulnerable Code
```javascript
Lines 173-213 of the vulnerable file.


  if (this._headers) {
    // Slow-case: when progressive API and header fields are passed.
    if (obj) {
      var keys = Object.keys(obj);
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        if (k) this.setHeader(k, obj[k]);
      }
    }
    // only progressive api is used
    headers = this._renderHeaders();
  } else {
    // only writeHead() called
    headers = obj;
  }

  statusCode |= 0;
  if (statusCode < 100 || statusCode > 999)
    throw new RangeError(`Invalid status code: ${statusCode}`);

  var statusLine = 'HTTP/1.1 ' + statusCode.toString() + ' ' +
                   this.statusMessage + CRLF;

  if (statusCode === 204 || statusCode === 304 ||
      (100 <= statusCode && statusCode <= 199)) {
    // RFC 2616, 10.2.5:
    // The 204 response MUST NOT include a message-body, and thus is always
    // terminated by the first empty line after the header fields.
    // RFC 2616, 10.3.5:
    // The 304 response MUST NOT contain a message-body, and thus is always
    // terminated by the first empty line after the header fields.
    // RFC 2616, 10.1 Informational 1xx:
    // This class of status code indicates a provisional response,
    // consisting only of the Status-Line and optional headers, and is
    // terminated by an empty line.
    this._hasBody = false;
  }

  // don't keep alive connections where the client expects 100 Continue
  // but we sent a final status; they may put extra bytes on the wire.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -191,6 +191,9 @@
   if (statusCode < 100 || statusCode > 999)
     throw new RangeError(`Invalid status code: ${statusCode}`);
 
+  if (common._checkInvalidHeaderChar(this.statusMessage))
+    throw new Error('Invalid character in statusMessage.');
+
   var statusLine = 'HTTP/1.1 ' + statusCode.toString() + ' ' +
                    this.statusMessage + CRLF;
 
```
