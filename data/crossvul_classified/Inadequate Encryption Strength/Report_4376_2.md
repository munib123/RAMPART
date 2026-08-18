# CrossVul Fix Pair: Inadequate Encryption Strength in python
**Pair ID:** 4376_2
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4376_2`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```python
Lines 90-132 of the vulnerable file.


    :rtype: ~tlslite.utils.rsakey.RSAKey
    :returns: An RSA key.

    :raises SyntaxError: If the key is not properly formatted.
    """
    for implementation in implementations:
        if implementation == "openssl" and cryptomath.m2cryptoLoaded:
            key = OpenSSL_RSAKey.parse(s, passwordCallback)
            break
        elif implementation == "python":
            key = Python_RSAKey.parsePEM(s)
            break
    else:
        raise ValueError("No acceptable implementations")

    return _parseKeyHelper(key, private, public)


def _parseKeyHelper(key, private, public):
    if private:
        if not key.hasPrivateKey():
            raise SyntaxError("Not a private key!")

    if public:
        return _createPublicKey(key)

    if private:
        if hasattr(key, "d"):
            return _createPrivateKey(key)
        else:
            return key

    return key

def parseAsPublicKey(s):
    """Parse a PEM-formatted public key.

    :type s: str
    :param s: A string containing a PEM-encoded public or private key.

    :rtype: ~tlslite.utils.rsakey.RSAKey
    :returns: An RSA public key.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -107,20 +107,22 @@
 
 
 def _parseKeyHelper(key, private, public):
-    if private:
-        if not key.hasPrivateKey():
-            raise SyntaxError("Not a private key!")
+    if private and not key.hasPrivateKey():
+        raise SyntaxError("Not a private key!")
 
     if public:
         return _createPublicKey(key)
 
     if private:
-        if hasattr(key, "d"):
+        if cryptomath.m2cryptoLoaded:
+            if type(key) == Python_RSAKey:
+                return _createPrivateKey(key)
+            assert type(key) in (OpenSSL_RSAKey, ), type(key)
+            return key
+        elif hasattr(key, "d"):
             return _createPrivateKey(key)
-        else:
-            return key
+    return key
 
-    return key
 
 def parseAsPublicKey(s):
     """Parse a PEM-formatted public key.
```
