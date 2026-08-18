# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 5206_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5206_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 361-401 of the vulnerable file.


    def unwrap(self, key, bitsize, ek, headers):
        self._check_key(key)
        rk = key.get_op_key('decrypt')
        cek = rk.decrypt(ek, self.padfn)
        if _bitsize(cek) != bitsize:
            raise InvalidJWEKeyLength(bitsize, _bitsize(cek))
        return cek


class _Rsa15(_RSA, JWAAlgorithm):

    name = 'RSA1_5'
    description = "RSAES-PKCS1-v1_5"
    keysize = 2048
    algorithm_usage_location = 'alg'
    algorithm_use = 'kex'

    def __init__(self):
        super(_Rsa15, self).__init__(padding.PKCS1v15())


class _RsaOaep(_RSA, JWAAlgorithm):

    name = 'RSA-OAEP'
    description = "RSAES OAEP using default parameters"
    keysize = 2048
    algorithm_usage_location = 'alg'
    algorithm_use = 'kex'

    def __init__(self):
        super(_RsaOaep, self).__init__(
            padding.OAEP(padding.MGF1(hashes.SHA1()),
                         hashes.SHA1(), None))


class _RsaOaep256(_RSA, JWAAlgorithm):  # noqa: ignore=N801

    name = 'RSA-OAEP-256'
    description = "RSAES OAEP using SHA-256 and MGF1 with SHA-256"
    keysize = 2048
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -378,6 +378,23 @@
 
     def __init__(self):
         super(_Rsa15, self).__init__(padding.PKCS1v15())
+
+    def unwrap(self, key, bitsize, ek, headers):
+        self._check_key(key)
+        # Address MMA attack by implementing RFC 3218 - 2.3.2. Random Filling
+        # provides a random cek that will cause the decryption engine to
+        # run to the end, but will fail decryption later.
+
+        # always generate a random cek so we spend roughly the
+        # same time as in the exception side of the branch
+        cek = _randombits(bitsize)
+        try:
+            cek = super(_Rsa15, self).unwrap(key, bitsize, ek, headers)
+            # always raise so we always run through the exception handling
+            # code in all cases
+            raise Exception('Dummy')
+        except Exception:  # pylint: disable=broad-except
+            return cek
 
 
 class _RsaOaep(_RSA, JWAAlgorithm):
```
