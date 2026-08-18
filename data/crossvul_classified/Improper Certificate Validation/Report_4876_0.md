# CrossVul Fix Pair: Improper Certificate Validation in javascript
**Pair ID:** 4876_0
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4876_0`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```javascript
Lines 73-113 of the vulnerable file.

  this.readyState = '';
  this.writeBuffer = [];
  this.policyPort = opts.policyPort || 843;
  this.rememberUpgrade = opts.rememberUpgrade || false;
  this.binaryType = null;
  this.onlyBinaryUpgrades = opts.onlyBinaryUpgrades;
  this.perMessageDeflate = false !== opts.perMessageDeflate ? (opts.perMessageDeflate || {}) : false;

  if (true === this.perMessageDeflate) this.perMessageDeflate = {};
  if (this.perMessageDeflate && null == this.perMessageDeflate.threshold) {
    this.perMessageDeflate.threshold = 1024;
  }

  // SSL options for Node.js client
  this.pfx = opts.pfx || null;
  this.key = opts.key || null;
  this.passphrase = opts.passphrase || null;
  this.cert = opts.cert || null;
  this.ca = opts.ca || null;
  this.ciphers = opts.ciphers || null;
  this.rejectUnauthorized = opts.rejectUnauthorized === undefined ? null : opts.rejectUnauthorized;

  // other options for Node.js client
  var freeGlobal = typeof global === 'object' && global;
  if (freeGlobal.global === freeGlobal) {
    if (opts.extraHeaders && Object.keys(opts.extraHeaders).length > 0) {
      this.extraHeaders = opts.extraHeaders;
    }
  }

  this.open();
}

Socket.priorWebsocketSuccess = false;

/**
 * Mix in `Emitter`.
 */

Emitter(Socket.prototype);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -90,7 +90,7 @@
   this.cert = opts.cert || null;
   this.ca = opts.ca || null;
   this.ciphers = opts.ciphers || null;
-  this.rejectUnauthorized = opts.rejectUnauthorized === undefined ? null : opts.rejectUnauthorized;
+  this.rejectUnauthorized = opts.rejectUnauthorized === undefined ? true : opts.rejectUnauthorized;
 
   // other options for Node.js client
   var freeGlobal = typeof global === 'object' && global;
```
