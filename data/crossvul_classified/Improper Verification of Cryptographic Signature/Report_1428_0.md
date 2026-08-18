# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in javascript
**Pair ID:** 1428_0
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1428_0`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```javascript
Lines 639-679 of the vulnerable file.

  // handle them (e.g. `await readToEnd(result.data); await result.verified` and
  // the data stream errors).
  verifiedSig.signature.catch(() => {});
  verifiedSig.verified.catch(() => {});

  return verifiedSig;
}

/**
 * Create list of objects containing signer's keyid and validity of signature
 * @param {Array<module:packet.Signature>} signatureList array of signature packets
 * @param {Array<module:packet.Literal>} literalDataList array of literal data packets
 * @param {Array<module:key.Key>} keys array of keys to verify signatures
 * @param {Date} date Verify the signature against the given date,
 *                    i.e. check signature creation time < date < expiration time
 * @returns {Promise<Array<{keyid: module:type/keyid,
 *                          valid: Boolean}>>} list of signer's keyid and validity of signature
 * @async
 */
export async function createVerificationObjects(signatureList, literalDataList, keys, date=new Date()) {
  return Promise.all(signatureList.map(async function(signature) {
    return createVerificationObject(signature, literalDataList, keys, date);
  }));
}

/**
 * Unwrap compressed message
 * @returns {module:message.Message} message Content of compressed message
 */
Message.prototype.unwrapCompressed = function() {
  const compressed = this.packets.filterByTag(enums.packet.compressed);
  if (compressed.length) {
    return new Message(compressed[0].packets);
  }
  return this;
};

/**
 * Append signature to unencrypted message object
 * @param {String|Uint8Array} detachedSignature The detached ASCII-armored or Uint8Array PGP signature
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -656,7 +656,9 @@
  * @async
  */
 export async function createVerificationObjects(signatureList, literalDataList, keys, date=new Date()) {
-  return Promise.all(signatureList.map(async function(signature) {
+  return Promise.all(signatureList.filter(function(signature) {
+    return ['text', 'binary'].includes(enums.read(enums.signature, signature.signatureType));
+  }).map(async function(signature) {
     return createVerificationObject(signature, literalDataList, keys, date);
   }));
 }
```
