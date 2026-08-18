# CrossVul Fix Pair: Cryptographic Issues in javascript
**Pair ID:** 1430_1
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1430_1`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```javascript
Lines 1-40 of the vulnerable file.

// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2015-2016 Decentral
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @fileoverview Key encryption and decryption for RFC 6637 ECDH
 * @requires crypto/public_key/elliptic/curve
 * @requires crypto/aes_kw
 * @requires crypto/cipher
 * @requires crypto/hash
 * @requires type/kdf_params
 * @requires enums
 * @requires util
 * @module crypto/public_key/elliptic/ecdh
 */

import BN from 'bn.js';
import Curve from './curves';
import aes_kw from '../../aes_kw';
import cipher from '../../cipher';
import hash from '../../hash';
import type_kdf_params from '../../../type/kdf_params';
import enums from '../../../enums';
import util from '../../../util';

// Build Param for ECDH algorithm (RFC 6637)
function buildEcdhParam(public_algo, oid, cipher_algo, hash_algo, fingerprint) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,6 +17,7 @@
 
 /**
  * @fileoverview Key encryption and decryption for RFC 6637 ECDH
+ * @requires bn.js
  * @requires crypto/public_key/elliptic/curve
  * @requires crypto/aes_kw
  * @requires crypto/cipher
@@ -49,10 +50,18 @@
 }
 
 // Key Derivation Function (RFC 6637)
-async function kdf(hash_algo, X, length, param) {
+async function kdf(hash_algo, S, length, param, curve, compat) {
+  const len = compat ?
+    S.byteLength() :
+    curve.curve.curve.p.byteLength();
+  // Note: this is not ideal, but the RFC's are unclear
+  // https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-02#appendix-B
+  const X = curve.curve.curve.type === 'mont' ?
+    S.toArrayLike(Uint8Array, 'le', len) :
+    S.toArrayLike(Uint8Array, 'be', len);
   const digest = await hash.digest(hash_algo, util.concatUint8Array([
     new Uint8Array([0, 0, 0, 1]),
-    new Uint8Array(X),
+    X,
     param
   ]));
   return digest.subarray(0, length);
@@ -61,24 +70,17 @@
 /**
  * Generate ECDHE ephemeral key and secret from public key
  *
- * @param  {module:type/oid}        oid                 Elliptic curve object identifier
- * @param  {module:enums.symmetric} cipher_algo         Symmetric cipher to use
- * @param  {module:enums.hash}      hash_algo           Hash algorithm to use
+ * @param  {Curve}                  curve        Elliptic curve object
  * @param  {Uint8Array}             Q                   Recipient public key
- * @param  {String}                 fingerprint         Recipient fingerprint
- * @returns {Promise<{V: Uint8Array, Z: Uint8Array}>}   Returns public part of ephemeral key and generated ephemeral secret
+ * @returns {Promise<{V: Uint8Array, S: BN}>}   Returns public part of ephemeral key and generated ephemeral secret
  * @async
  */
-async function genPublicEphemeralKey(oid, cipher_algo, hash_algo, Q, fingerprint) {
-  const curve = new Curve(oid);
-  const param = buildEcdhParam(enums.publicKey.ecdh, oid, cipher_algo, hash_algo, fingerprint);
-  cipher_algo = enums.read(enums.symmetric, cipher_algo);
+async function genPublicEphemeralKey(curve, Q) {
   const v = await curve.genKeyPair();
   Q = curve.keyFromPublic(Q);
+  const V = new Uint8Array(v.getPublic());
   const S = v.derive(Q);
-  const V = new Uint8Array(v.getPublic());
-  const Z = await kdf(hash_algo, S, cipher[cipher_algo].keySize, param);
-  return { V, Z };
+  return { V, S };
 }
 
 /**
@@ -94,33 +96,28 @@
  * @async
  */
 async function encrypt(oid, cipher_algo, hash_algo, m, Q, fingerprint) {
-  const { V, Z } = await genPublicEphemeralKey(oid, cipher_algo, hash_algo, Q, fingerprint);
-  return {
-      V: new BN(V),
-      C: aes_kw.wrap(Z, m.toString())
-  };
+  const curve = new Curve(oid);
+  const { V, S } = await genPublicEphemeralKey(curve, Q);
+  const param = buildEcdhParam(enums.publicKey.ecdh, oid, cipher_algo, hash_algo, fingerprint);
+  cipher_algo = enums.read(enums.symmetric, cipher_algo);
+  const Z = await kdf(hash_algo, S, cipher[cipher_algo].keySize, param, curve, false);
+  const C = aes_kw.wrap(Z, m.toString());
+  return { V, C };
 }
 
 /**
  * Generate ECDHE secret from private key and public part of ephemeral key
  *
- * @param  {module:type/oid}        oid          Elliptic curve object identifier
- * @param  {module:enums.symmetric} cipher_algo  Symmetric cipher to use
- * @param  {module:enums.hash}      hash_algo    Hash algorithm to use
+ * @param  {Curve}                  curve        Elliptic curve object
  * @param  {Uint8Array}             V            Public part of ephemeral key
  * @param  {Uint8Array}             d            Recipient private key
- * @param  {String}                 fingerprint  Recipient fingerprint
- * @returns {Promise<Uint8Array>}                Generated ephemeral secret
+ * @returns {Promise<BN>}                        Generated ephemeral secret
  * @async
  */
-async function genPrivateEphemeralKey(oid, cipher_algo, hash_algo, V, d, fingerprint) {
-  const curve = new Curve(oid);
-  const param = buildEcdhParam(enums.publicKey.ecdh, oid, cipher_algo, hash_algo, fingerprint);
-  cipher_algo = enums.read(enums.symmetric, cipher_algo);
+async function genPrivateEphemeralKey(curve, V, d) {
   V = curve.keyFromPublic(V);
   d = curve.keyFromPrivate(d);
-  const S = d.derive(V);
-  return kdf(hash_algo, S, cipher[cipher_algo].keySize, param);
+  return d.derive(V);
 }
 
 /**
@@ -137,8 +134,17 @@
  * @async
  */
 async function decrypt(oid, cipher_algo, hash_algo, V, C, d, fingerprint) {
-  const Z = await genPrivateEphemeralKey(oid, cipher_algo, hash_algo, V, d, fingerprint);
+  const curve = new Curve(oid);
+  const S = await genPrivateEphemeralKey(curve, V, d);
+  const param = buildEcdhParam(enums.publicKey.ecdh, oid, cipher_algo, hash_algo, fingerprint);
+  cipher_algo = enums.read(enums.symmetric, cipher_algo);
+  try {
+    const Z = await kdf(hash_algo, S, cipher[cipher_algo].keySize, param, curve, false);
+    return new BN(aes_kw.unwrap(Z, C));
+  } catch(e) {}
+  // Work around old OpenPGP.js bug.
+  const Z = await kdf(hash_algo, S, cipher[cipher_algo].keySize, param, curve, true);
   return new BN(aes_kw.unwrap(Z, C));
 }
 
-export default { encrypt, decrypt, genPublicEphemeralKey, genPrivateEphemeralKey };
+export default { encrypt, decrypt, genPublicEphemeralKey, genPrivateEphemeralKey, buildEcdhParam, kdf };
```
