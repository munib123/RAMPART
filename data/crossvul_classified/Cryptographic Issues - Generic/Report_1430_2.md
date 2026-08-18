# CrossVul Fix Pair: Cryptographic Issues in javascript
**Pair ID:** 1430_2
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1430_2`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```javascript
Lines 180-220 of the vulnerable file.

      const key = curve.keyFromPublic(key_data.p256.pub);
      expect(
        key.verify(signature_data.message, signature_data.signature, 8, signature_data.hashed)
      ).to.eventually.be.false.notify(done);
    });
    it('Signature generation', function () {
      const curve = new elliptic_curves.Curve('p256');
      let key = curve.keyFromPrivate(key_data.p256.priv);
      return key.sign(signature_data.message, 8, signature_data.hashed).then(async ({ r, s }) => {
        const signature = { r: new Uint8Array(r.toArray()), s: new Uint8Array(s.toArray()) };
        key = curve.keyFromPublic(key_data.p256.pub);
        await expect(
          key.verify(signature_data.message, signature, 8, signature_data.hashed)
        ).to.eventually.be.true;
      });
    });
    it('Shared secret generation', function (done) {
      const curve = new elliptic_curves.Curve('p256');
      let key1 = curve.keyFromPrivate(key_data.p256.priv);
      let key2 = curve.keyFromPublic(signature_data.pub);
      const shared1 = openpgp.util.Uint8Array_to_hex(key1.derive(key2));
      key1 = curve.keyFromPublic(key_data.p256.pub);
      key2 = curve.keyFromPrivate(signature_data.priv);
      const shared2 = openpgp.util.Uint8Array_to_hex(key2.derive(key1));
      expect(shared1).to.equal(shared2);
      done();
    });
  });
  describe('ECDSA signature', function () {
    const verify_signature = async function (oid, hash, r, s, message, pub) {
      if (openpgp.util.isString(message)) {
        message = openpgp.util.str_to_Uint8Array(message);
      } else if (!openpgp.util.isUint8Array(message)) {
        message = new Uint8Array(message);
      }
      const ecdsa = elliptic_curves.ecdsa;
      return ecdsa.verify(
        oid, hash, { r: new Uint8Array(r), s: new Uint8Array(s) }, message, new Uint8Array(pub), await openpgp.crypto.hash.digest(hash, message)
      );
    };
    const secp256k1_dummy_value = new Uint8Array([
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -197,10 +197,10 @@
       const curve = new elliptic_curves.Curve('p256');
       let key1 = curve.keyFromPrivate(key_data.p256.priv);
       let key2 = curve.keyFromPublic(signature_data.pub);
-      const shared1 = openpgp.util.Uint8Array_to_hex(key1.derive(key2));
+      const shared1 = openpgp.util.Uint8Array_to_hex(key1.derive(key2).toArrayLike(Uint8Array));
       key1 = curve.keyFromPublic(key_data.p256.pub);
       key2 = curve.keyFromPrivate(signature_data.priv);
-      const shared2 = openpgp.util.Uint8Array_to_hex(key2.derive(key1));
+      const shared2 = openpgp.util.Uint8Array_to_hex(key2.derive(key1).toArrayLike(Uint8Array));
       expect(shared1).to.equal(shared2);
       done();
     });
@@ -424,25 +424,36 @@
   async function genPublicEphemeralKey(curve, Q, fingerprint) {
     const curveObj = new openpgp.crypto.publicKey.elliptic.Curve(curve);
     const oid = new openpgp.OID(curveObj.oid);
-    return openpgp.crypto.publicKey.elliptic.ecdh.genPublicEphemeralKey(
-        oid,
-        curveObj.cipher,
-        curveObj.hash,
-        Q,
-        fingerprint
-    );
+    const { V, S } = await openpgp.crypto.publicKey.elliptic.ecdh.genPublicEphemeralKey(
+      curveObj, Q
+    );
+    let cipher_algo = curveObj.cipher;
+    const hash_algo = curveObj.hash;
+    const param = openpgp.crypto.publicKey.elliptic.ecdh.buildEcdhParam(
+      openpgp.enums.publicKey.ecdh, oid, cipher_algo, hash_algo, fingerprint
+    );
+    cipher_algo = openpgp.enums.read(openpgp.enums.symmetric, cipher_algo);
+    const Z = await openpgp.crypto.publicKey.elliptic.ecdh.kdf(
+      hash_algo, S, openpgp.crypto.cipher[cipher_algo].keySize, param, curveObj, false
+    );
+    return { V, Z };
   }
   async function genPrivateEphemeralKey(curve, V, d, fingerprint) {
     const curveObj = new openpgp.crypto.publicKey.elliptic.Curve(curve);
     const oid = new openpgp.OID(curveObj.oid);
-    return openpgp.crypto.publicKey.elliptic.ecdh.genPrivateEphemeralKey(
-        oid,
-        curveObj.cipher,
-        curveObj.hash,
-        V,
-        d,
-        fingerprint
-    );
+    const S = await openpgp.crypto.publicKey.elliptic.ecdh.genPrivateEphemeralKey(
+      curveObj, V, d
+    );
+    let cipher_algo = curveObj.cipher;
+    const hash_algo = curveObj.hash;
+    const param = openpgp.crypto.publicKey.elliptic.ecdh.buildEcdhParam(
+      openpgp.enums.publicKey.ecdh, oid, cipher_algo, hash_algo, fingerprint
+    );
+    cipher_algo = openpgp.enums.read(openpgp.enums.symmetric, cipher_algo);
+    const Z = await openpgp.crypto.publicKey.elliptic.ecdh.kdf(
+      hash_algo, S, openpgp.crypto.cipher[cipher_algo].keySize, param, curveObj, false
+    );
+    return Z;
   }
   const ECDHE_VZ1 = await genPublicEphemeralKey("curve25519", Q1, fingerprint1);
   const ECDHE_VZ2 = await genPublicEphemeralKey("curve25519", Q2, fingerprint1);
```
