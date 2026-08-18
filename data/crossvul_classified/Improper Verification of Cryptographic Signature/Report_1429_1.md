# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in javascript
**Pair ID:** 1429_1
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1429_1`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```javascript
Lines 1-3 of the vulnerable file.

describe('Security', function () {
  require('./message_signature_bypass');
});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,4 @@
 describe('Security', function () {
   require('./message_signature_bypass');
+  require('./unsigned_subpackets');
 });
```
