# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in javascript
**Pair ID:** 4118_1
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4118_1`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```javascript
Lines 1-16 of the vulnerable file.

const PassiveConnector = require('../../connector/passive');

module.exports = {
  directive: 'EPSV',
  handler: function () {
    this.connector = new PassiveConnector(this);
    return this.connector.setupServer()
    .then((server) => {
      const {port} = server.address();

      return this.reply(229, `EPSV OK (|||${port}|)`);
    });
  },
  syntax: '{{cmd}} [<protocol>]',
  description: 'Initiate passive mode'
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,13 +2,17 @@
 
 module.exports = {
   directive: 'EPSV',
-  handler: function () {
+  handler: function ({log}) {
     this.connector = new PassiveConnector(this);
     return this.connector.setupServer()
     .then((server) => {
       const {port} = server.address();
 
       return this.reply(229, `EPSV OK (|||${port}|)`);
+    })
+    .catch((err) => {
+      log.error(err);
+      return this.reply(err.code || 425, err.message);
     });
   },
   syntax: '{{cmd}} [<protocol>]',
```
