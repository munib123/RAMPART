# CrossVul Fix Pair: Cryptographic Issues in python
**Pair ID:** 3699_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3699_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```python
Lines 1-31 of the vulnerable file.

"""Encryption module that uses pycryptopp or pycrypto"""
try:
    # Pycryptopp is preferred over Crypto because Crypto has had
    # various periods of not being maintained, and pycryptopp uses
    # the Crypto++ library which is generally considered the 'gold standard'
    # of crypto implementations
    from pycryptopp.cipher import aes

    def aesEncrypt(data, key):
        cipher = aes.AES(key)
        return cipher.process(data)

    # magic.
    aesDecrypt = aesEncrypt

except ImportError:
    from Crypto.Cipher import AES

    def aesEncrypt(data, key):
        cipher = AES.new(key)

        data = data + (" " * (16 - (len(data) % 16)))
        return cipher.encrypt(data)

    def aesDecrypt(data, key):
        cipher = AES.new(key)

        return cipher.decrypt(data).rstrip()

def getKeyLength():
    return 32
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,17 +15,18 @@
 
 except ImportError:
     from Crypto.Cipher import AES
+    from Crypto.Util import Counter
 
     def aesEncrypt(data, key):
-        cipher = AES.new(key)
+        cipher = AES.new(key, AES.MODE_CTR,
+                         counter=Counter.new(128, initial_value=0))
 
-        data = data + (" " * (16 - (len(data) % 16)))
         return cipher.encrypt(data)
 
     def aesDecrypt(data, key):
-        cipher = AES.new(key)
-
-        return cipher.decrypt(data).rstrip()
+        cipher = AES.new(key, AES.MODE_CTR,
+                         counter=Counter.new(128, initial_value=0))
+        return cipher.decrypt(data)
 
 def getKeyLength():
     return 32
```
