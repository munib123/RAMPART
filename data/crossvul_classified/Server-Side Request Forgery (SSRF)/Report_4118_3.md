# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in javascript
**Pair ID:** 4118_3
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4118_3`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```javascript
Lines 1-25 of the vulnerable file.

const _ = require('lodash');
const ActiveConnector = require('../../connector/active');

module.exports = {
  directive: 'PORT',
  handler: function ({log, command} = {}) {
    this.connector = new ActiveConnector(this);

    const rawConnection = _.get(command, 'arg', '').split(',');
    if (rawConnection.length !== 6) return this.reply(425);

    const ip = rawConnection.slice(0, 4).join('.');
    const portBytes = rawConnection.slice(4).map((p) => parseInt(p));
    const port = portBytes[0] * 256 + portBytes[1];

    return this.connector.setupConnection(ip, port)
    .then(() => this.reply(200))
    .catch((err) => {
      log.error(err);
      return this.reply(425);
    });
  },
  syntax: '{{cmd}} <x>,<x>,<x>,<x>,<y>,<y>',
  description: 'Specifies an address and port to which the server should connect'
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,7 +17,7 @@
     .then(() => this.reply(200))
     .catch((err) => {
       log.error(err);
-      return this.reply(425);
+      return this.reply(err.code || 425, err.message);
     });
   },
   syntax: '{{cmd}} <x>,<x>,<x>,<x>,<y>,<y>',
```
