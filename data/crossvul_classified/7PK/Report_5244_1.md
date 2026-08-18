# CrossVul Fix Pair: 7PK in python
**Pair ID:** 5244_1
**Vulnerability Class:** 7PK
**CWE:** CWE-361
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5244_1`)

## Vulnerability Information & PoC

## Description
7PK - Time and State

## Vulnerable Code
```python
Lines 1-23 of the vulnerable file.


import base64


def calculate_at_hash(access_token, hash_alg):
    """Helper method for calculating an access token
    hash, as described in http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken

    Its value is the base64url encoding of the left-most half of the hash of the octets
    of the ASCII representation of the access_token value, where the hash algorithm
    used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE
    Header. For instance, if the alg is RS256, hash the access_token value with SHA-256,
    then take the left-most 128 bits and base64url encode them. The at_hash value is a
    case sensitive string.

    Args:
        access_token (str): An access token string.
        hash_alg (callable): A callable returning a hash object, e.g. hashlib.sha256

    """
    hash_digest = hash_alg(access_token.encode('utf-8')).digest()
    cut_at = int(len(hash_digest) / 2)
    truncated = hash_digest[:cut_at]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,6 @@
 
 import base64
+import hmac
 
 
 def calculate_at_hash(access_token, hash_alg):
@@ -58,3 +59,27 @@
         delta (timedelta): A timedelta to convert to seconds.
     """
     return delta.days * 24 * 60 * 60 + delta.seconds
+
+
+def constant_time_string_compare(a, b):
+    """Helper for comparing string in constant time, independent
+    of the python version being used.
+
+    Args:
+        a (str): A string to compare
+        b (str): A string to compare
+    """
+
+    try:
+        return hmac.compare_digest(a, b)
+    except AttributeError:
+
+        if len(a) != len(b):
+            return False
+
+        result = 0
+
+        for x, y in zip(a, b):
+            result |= ord(x) ^ ord(y)
+
+        return result == 0
```
