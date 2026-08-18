# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in javascript
**Pair ID:** 4118_0
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4118_0`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```javascript
Lines 1-22 of the vulnerable file.

const _ = require('lodash');
const ActiveConnector = require('../../connector/active');

const FAMILY = {
  1: 4,
  2: 6
};

module.exports = {
  directive: 'EPRT',
  handler: function ({command} = {}) {
    const [, protocol, ip, port] = _.chain(command).get('arg', '').split('|').value();
    const family = FAMILY[protocol];
    if (!family) return this.reply(504, 'Unknown network protocol');

    this.connector = new ActiveConnector(this);
    return this.connector.setupConnection(ip, port, family)
    .then(() => this.reply(200));
  },
  syntax: '{{cmd}} |<protocol>|<address>|<port>|',
  description: 'Specifies an address and port to which the server should connect'
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,14 +8,18 @@
 
 module.exports = {
   directive: 'EPRT',
-  handler: function ({command} = {}) {
+  handler: function ({log, command} = {}) {
     const [, protocol, ip, port] = _.chain(command).get('arg', '').split('|').value();
     const family = FAMILY[protocol];
     if (!family) return this.reply(504, 'Unknown network protocol');
 
     this.connector = new ActiveConnector(this);
     return this.connector.setupConnection(ip, port, family)
-    .then(() => this.reply(200));
+    .then(() => this.reply(200))
+    .catch((err) => {
+      log.error(err);
+      return this.reply(err.code || 425, err.message);
+    });
   },
   syntax: '{{cmd}} |<protocol>|<address>|<port>|',
   description: 'Specifies an address and port to which the server should connect'
```
