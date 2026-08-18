# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in python
**Pair ID:** 5871_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5871_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```python
Lines 588-628 of the vulnerable file.

        self.no_late_update()
        self.loopback()

    def shortDescription(self):
        return self.description

class RoundtripTest(unittest.TestCase):
    def __init__(self, module, params):
        from Crypto import Random
        unittest.TestCase.__init__(self)
        self.module = module
        self.iv = Random.get_random_bytes(module.block_size)
        self.key = b(params['key'])
        self.plaintext = 100 * b(params['plaintext'])
        self.module_name = params.get('module_name', None)

    def shortDescription(self):
        return """%s .decrypt() output of .encrypt() should not be garbled""" % (self.module_name,)

    def runTest(self):
        for mode in (self.module.MODE_ECB, self.module.MODE_CBC, self.module.MODE_CFB, self.module.MODE_OFB, self.module.MODE_OPENPGP):
            encryption_cipher = self.module.new(a2b_hex(self.key), mode, self.iv)
            ciphertext = encryption_cipher.encrypt(self.plaintext)

            if mode != self.module.MODE_OPENPGP:
                decryption_cipher = self.module.new(a2b_hex(self.key), mode, self.iv)
            else:
                eiv = ciphertext[:self.module.block_size+2]
                ciphertext = ciphertext[self.module.block_size+2:]
                decryption_cipher = self.module.new(a2b_hex(self.key), mode, eiv)
            decrypted_plaintext = decryption_cipher.decrypt(ciphertext)
            self.assertEqual(self.plaintext, decrypted_plaintext)

class PGPTest(unittest.TestCase):
    def __init__(self, module, params):
        unittest.TestCase.__init__(self)
        self.module = module
        self.key = b(params['key'])

    def shortDescription(self):
        return "MODE_PGP was implemented incorrectly and insecurely. It's completely banished now."
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -605,18 +605,33 @@
         return """%s .decrypt() output of .encrypt() should not be garbled""" % (self.module_name,)
 
     def runTest(self):
-        for mode in (self.module.MODE_ECB, self.module.MODE_CBC, self.module.MODE_CFB, self.module.MODE_OFB, self.module.MODE_OPENPGP):
+
+        ## ECB mode
+        mode = self.module.MODE_ECB
+        encryption_cipher = self.module.new(a2b_hex(self.key), mode)
+        ciphertext = encryption_cipher.encrypt(self.plaintext)
+        decryption_cipher = self.module.new(a2b_hex(self.key), mode)
+        decrypted_plaintext = decryption_cipher.decrypt(ciphertext)
+        self.assertEqual(self.plaintext, decrypted_plaintext)
+
+        ## OPENPGP mode
+        mode = self.module.MODE_OPENPGP
+        encryption_cipher = self.module.new(a2b_hex(self.key), mode, self.iv)
+        eiv_ciphertext = encryption_cipher.encrypt(self.plaintext)
+        eiv = eiv_ciphertext[:self.module.block_size+2]
+        ciphertext = eiv_ciphertext[self.module.block_size+2:]
+        decryption_cipher = self.module.new(a2b_hex(self.key), mode, eiv)
+        decrypted_plaintext = decryption_cipher.decrypt(ciphertext)
+        self.assertEqual(self.plaintext, decrypted_plaintext)
+
+        ## All other non-AEAD modes (but CTR)
+        for mode in (self.module.MODE_CBC, self.module.MODE_CFB, self.module.MODE_OFB):
             encryption_cipher = self.module.new(a2b_hex(self.key), mode, self.iv)
             ciphertext = encryption_cipher.encrypt(self.plaintext)
-
-            if mode != self.module.MODE_OPENPGP:
-                decryption_cipher = self.module.new(a2b_hex(self.key), mode, self.iv)
-            else:
-                eiv = ciphertext[:self.module.block_size+2]
-                ciphertext = ciphertext[self.module.block_size+2:]
-                decryption_cipher = self.module.new(a2b_hex(self.key), mode, eiv)
+            decryption_cipher = self.module.new(a2b_hex(self.key), mode, self.iv)
             decrypted_plaintext = decryption_cipher.decrypt(ciphertext)
             self.assertEqual(self.plaintext, decrypted_plaintext)
+
 
 class PGPTest(unittest.TestCase):
     def __init__(self, module, params):
```
