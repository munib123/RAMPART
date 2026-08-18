# CrossVul Fix Pair: 7PK in python
**Pair ID:** 5244_0
**Vulnerability Class:** 7PK
**CWE:** CWE-361
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5244_0`)

## Vulnerability Information & PoC

## Description
7PK - Time and State

## Vulnerable Code
```python
Lines 2-42 of the vulnerable file.

import base64
import hashlib
import hmac
import struct
import six
import sys

import Crypto.Hash.SHA256
import Crypto.Hash.SHA384
import Crypto.Hash.SHA512

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Util.asn1 import DerSequence

import ecdsa

from jose.constants import ALGORITHMS
from jose.exceptions import JWKError
from jose.utils import base64url_decode

# PyCryptodome's RSA module doesn't have PyCrypto's _RSAobj class
# Instead it has a class named RsaKey, which serves the same purpose.
if hasattr(RSA, '_RSAobj'):
    _RSAKey = RSA._RSAobj
else:
    _RSAKey = RSA.RsaKey

# Deal with integer compatibilities between Python 2 and 3.
# Using `from builtins import int` is not supported on AppEngine.
if sys.version_info > (3,):
    long = int


def int_arr_to_long(arr):
    return long(''.join(["%02x" % byte for byte in arr]), 16)


def base64_to_long(data):
    if isinstance(data, six.text_type):
        data = data.encode("ascii")
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,7 @@
 from jose.constants import ALGORITHMS
 from jose.exceptions import JWKError
 from jose.utils import base64url_decode
+from jose.utils import constant_time_string_compare
 
 # PyCryptodome's RSA module doesn't have PyCrypto's _RSAobj class
 # Instead it has a class named RsaKey, which serves the same purpose.
@@ -159,7 +160,7 @@
         return hmac.new(self.prepared_key, msg, self.hash_alg).digest()
 
     def verify(self, msg, sig):
-        return sig == self.sign(msg)
+        return constant_time_string_compare(sig, self.sign(msg))
 
 
 class RSAKey(Key):
```
