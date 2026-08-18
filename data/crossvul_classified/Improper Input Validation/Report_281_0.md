# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 281_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `281_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 496-536 of the vulnerable file.

  websocketProxies.forEach(function (wsProxy) {
    this.listeningApp.on('upgrade', wsProxy.upgrade);
  }, this);
}

Server.prototype.use = function () {
  // eslint-disable-next-line
  this.app.use.apply(this.app, arguments);
};

Server.prototype.setContentHeaders = function (req, res, next) {
  if (this.headers) {
    for (const name in this.headers) { // eslint-disable-line
      res.setHeader(name, this.headers[name]);
    }
  }

  next();
};

Server.prototype.checkHost = function (headers) {
  // allow user to opt-out this security check, at own risk
  if (this.disableHostCheck) return true;

  // get the Host header and extract hostname
  // we don't care about port not matching
  const hostHeader = headers.host;
  if (!hostHeader) return false;

  // use the node url-parser to retrieve the hostname from the host-header.
  const hostname = url.parse(`//${hostHeader}`, false, true).hostname;

  // always allow requests with explicit IPv4 or IPv6-address.
  // A note on IPv6 addresses: hostHeader will always contain the brackets denoting
  // an IPv6-address in URLs, these are removed from the hostname in url.parse(),
  // so we have the pure IPv6-address in hostname.
  if (ip.isV4Format(hostname) || ip.isV6Format(hostname)) return true;

  // always allow localhost host, for convience
  if (hostname === 'localhost') return true;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -513,13 +513,15 @@
   next();
 };
 
-Server.prototype.checkHost = function (headers) {
+Server.prototype.checkHost = function (headers, headerToCheck) {
   // allow user to opt-out this security check, at own risk
   if (this.disableHostCheck) return true;
 
+  if (!headerToCheck) headerToCheck = "host";
+
   // get the Host header and extract hostname
   // we don't care about port not matching
-  const hostHeader = headers.host;
+  const hostHeader = headers[headerToCheck];
   if (!hostHeader) return false;
 
   // use the node url-parser to retrieve the hostname from the host-header.
@@ -586,6 +588,11 @@
       if (!conn) return;
       if (!this.checkHost(conn.headers)) {
         this.sockWrite([conn], 'error', 'Invalid Host header');
+        conn.close();
+        return;
+      }
+      if (!this.checkHost(conn.headers, "origin")) {
+        this.sockWrite([conn], 'error', 'Invalid Origin header');
         conn.close();
         return;
       }
```
