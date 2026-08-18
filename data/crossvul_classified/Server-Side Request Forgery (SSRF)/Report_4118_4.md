# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in javascript
**Pair ID:** 4118_4
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4118_4`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```javascript
Lines 1-23 of the vulnerable file.

const {Socket} = require('net');
const tls = require('tls');
const Promise = require('bluebird');
const Connector = require('./base');

class Active extends Connector {
  constructor(connection) {
    super(connection);
    this.type = 'active';
  }

  waitForConnection({timeout = 5000, delay = 250} = {}) {
    const checkSocket = () => {
      if (this.dataSocket && this.dataSocket.connected) {
        return Promise.resolve(this.dataSocket);
      }
      return Promise.resolve().delay(delay)
      .then(() => checkSocket());
    };

    return checkSocket().timeout(timeout);
  }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,9 @@
 const {Socket} = require('net');
 const tls = require('tls');
+const ip = require('ip');
 const Promise = require('bluebird');
 const Connector = require('./base');
+const {SocketError} = require('../errors');
 
 class Active extends Connector {
   constructor(connection) {
@@ -27,6 +29,10 @@
 
     return closeExistingServer()
     .then(() => {
+      if (!ip.isEqual(this.connection.commandSocket.remoteAddress, host)) {
+        throw new SocketError('The given address is not yours', 500);
+      }
+
       this.dataSocket = new Socket();
       this.dataSocket.on('error', (err) => this.server && this.server.emit('client-error', {connection: this.connection, context: 'dataSocket', error: err}));
       this.dataSocket.connect({host, port, family}, () => {
```
