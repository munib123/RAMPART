# CrossVul Fix Pair: Inadequate Encryption Strength in python
**Pair ID:** 4376_3
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4376_3`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```python
Lines 1-31 of the vulnerable file.

# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""OpenSSL/M2Crypto RSA implementation."""

from .cryptomath import *

from .rsakey import *
from .python_rsakey import Python_RSAKey
from .compat import compatAscii2Bytes

#copied from M2Crypto.util.py, so when we load the local copy of m2
#we can still use it
def password_callback(v, prompt1='Enter private key passphrase:',
                           prompt2='Verify passphrase:'):
    from getpass import getpass
    while 1:
        try:
            p1=getpass(prompt1)
            if v:
                p2=getpass(prompt2)
                if p1==p2:
                    break
            else:
                break
        except KeyboardInterrupt:
            return None
    return p1


if m2cryptoLoaded:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,6 +8,7 @@
 from .rsakey import *
 from .python_rsakey import Python_RSAKey
 from .compat import compatAscii2Bytes
+import sys
 
 #copied from M2Crypto.util.py, so when we load the local copy of m2
 #we can still use it
@@ -65,11 +66,19 @@
             c = bytesToNumber(bytearray(s))
             return c
 
+        def _raw_private_key_op_bytes(self, message):
+            return bytearray(m2.rsa_private_encrypt(self.rsa, bytes(message),
+                                                    m2.no_padding))
+
         def _rawPublicKeyOp(self, c):
             b = numberToByteArray(c, numBytes(self.n))
             s = m2.rsa_public_decrypt(self.rsa, bytes(b), m2.no_padding)
             m = bytesToNumber(bytearray(s))
             return m
+
+        def _raw_public_key_op_bytes(self, ciphertext):
+            return bytearray(m2.rsa_public_decrypt(self.rsa, bytes(ciphertext),
+                                                   m2.no_padding))
 
         def acceptsPassword(self): return True
 
@@ -146,6 +155,13 @@
                         key._hasPrivateKey = False
                     else:
                         raise SyntaxError()
+                    if key._hasPrivateKey:
+                        if sys.version_info < (3, 0):
+                            b64_key = str(key.write())
+                        else:
+                            b64_key = str(key.write(), "ascii")
+                        py_key = Python_RSAKey.parsePEM(b64_key)
+                        key.d = py_key.d
                     return key
                 finally:
                     m2.bio_free(bio)
```
