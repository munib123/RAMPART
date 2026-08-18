# CrossVul Fix Pair: Cryptographic Issues in javascript
**Pair ID:** 1430_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1430_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```javascript
Lines 3-43 of the vulnerable file.

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

// The GPG4Browsers crypto interface

/**
 * @fileoverview Provides functions for asymmetric encryption and decryption as
 * well as key generation and parameter handling for all public-key cryptosystems.
 * @requires crypto/public_key
 * @requires crypto/cipher
 * @requires crypto/random
 * @requires type/ecdh_symkey
 * @requires type/kdf_params
 * @requires type/mpi
 * @requires type/oid
 * @requires enums
 * @requires util
 * @module crypto/crypto
 */

import publicKey from './public_key';
import cipher from './cipher';
import random from './random';
import type_ecdh_symkey from '../type/ecdh_symkey';
import type_kdf_params from '../type/kdf_params';
import type_mpi from '../type/mpi';
import type_oid from '../type/oid';
import enums from '../enums';
import util from '../util';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,6 +20,7 @@
 /**
  * @fileoverview Provides functions for asymmetric encryption and decryption as
  * well as key generation and parameter handling for all public-key cryptosystems.
+ * @requires bn.js
  * @requires crypto/public_key
  * @requires crypto/cipher
  * @requires crypto/random
@@ -32,6 +33,7 @@
  * @module crypto/crypto
  */
 
+import BN from 'bn.js';
 import publicKey from './public_key';
 import cipher from './cipher';
 import random from './random';
@@ -89,9 +91,9 @@
           const oid = pub_params[0];
           const Q = pub_params[1].toUint8Array();
           const kdf_params = pub_params[2];
-          const res = await publicKey.elliptic.ecdh.encrypt(
+          const { V, C } = await publicKey.elliptic.ecdh.encrypt(
             oid, kdf_params.cipher, kdf_params.hash, data, Q, fingerprint);
-          return constructParams(types, [res.V, res.C]);
+          return constructParams(types, [new BN(V), C]);
         }
         default:
           return [];
```
