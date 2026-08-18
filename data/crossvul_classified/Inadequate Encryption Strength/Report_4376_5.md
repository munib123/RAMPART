# CrossVul Fix Pair: Inadequate Encryption Strength in python
**Pair ID:** 4376_5
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4376_5`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```python
Lines 69-109 of the vulnerable file.

        return m

    def acceptsPassword(self): return False

    def generate(bits):
        key = Python_RSAKey()
        p = getRandomPrime(bits//2, False)
        q = getRandomPrime(bits//2, False)
        t = lcm(p-1, q-1)
        key.n = p * q
        key.e = 65537
        key.d = invMod(key.e, t)
        key.p = p
        key.q = q
        key.dP = key.d % (p-1)
        key.dQ = key.d % (q-1)
        key.qInv = invMod(q, p)
        return key
    generate = staticmethod(generate)

    def parsePEM(s, passwordCallback=None):
        """Parse a string containing a PEM-encoded <privateKey>."""

        if pemSniff(s, "PRIVATE KEY"):
            bytes = dePem(s, "PRIVATE KEY")
            return Python_RSAKey._parsePKCS8(bytes)
        elif pemSniff(s, "RSA PRIVATE KEY"):
            bytes = dePem(s, "RSA PRIVATE KEY")
            return Python_RSAKey._parseSSLeay(bytes)
        else:
            raise SyntaxError("Not a PEM private key file")
    parsePEM = staticmethod(parsePEM)

    def _parsePKCS8(bytes):
        p = ASN1Parser(bytes)

        # first element in PrivateKeyInfo is an INTEGER
        version = p.getChild(0).value
        if bytesToNumber(version) != 0:
            raise SyntaxError("Unrecognized PKCS8 version")

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -86,79 +86,8 @@
         return key
     generate = staticmethod(generate)
 
+    @staticmethod
     def parsePEM(s, passwordCallback=None):
         """Parse a string containing a PEM-encoded <privateKey>."""
-
-        if pemSniff(s, "PRIVATE KEY"):
-            bytes = dePem(s, "PRIVATE KEY")
-            return Python_RSAKey._parsePKCS8(bytes)
-        elif pemSniff(s, "RSA PRIVATE KEY"):
-            bytes = dePem(s, "RSA PRIVATE KEY")
-            return Python_RSAKey._parseSSLeay(bytes)
-        else:
-            raise SyntaxError("Not a PEM private key file")
-    parsePEM = staticmethod(parsePEM)
-
-    def _parsePKCS8(bytes):
-        p = ASN1Parser(bytes)
-
-        # first element in PrivateKeyInfo is an INTEGER
-        version = p.getChild(0).value
-        if bytesToNumber(version) != 0:
-            raise SyntaxError("Unrecognized PKCS8 version")
-
-        # second element in PrivateKeyInfo is a SEQUENCE of type
-        # AlgorithmIdentifier
-        algIdent = p.getChild(1)
-        seqLen = algIdent.getChildCount()
-        # first item of AlgorithmIdentifier is an OBJECT (OID)
-        oid = algIdent.getChild(0)
-        if list(oid.value) == [42, 134, 72, 134, 247, 13, 1, 1, 1]:
-            keyType = "rsa"
-        elif list(oid.value) == [42, 134, 72, 134, 247, 13, 1, 1, 10]:
-            keyType = "rsa-pss"
-        else:
-            raise SyntaxError("Unrecognized AlgorithmIdentifier: {0}"
-                              .format(list(oid.value)))
-        # second item of AlgorithmIdentifier are parameters (defined by
-        # above algorithm)
-        if keyType == "rsa":
-            if seqLen != 2:
-                raise SyntaxError("Missing parameters for RSA algorithm ID")
-            parameters = algIdent.getChild(1)
-            if parameters.value != bytearray(0):
-                raise SyntaxError("RSA parameters are not NULL")
-        else:  # rsa-pss
-            pass  # ignore parameters - don't apply restrictions
-
-        if seqLen > 2:
-            raise SyntaxError("Invalid encoding of AlgorithmIdentifier")
-
-        #Get the privateKey
-        privateKeyP = p.getChild(2)
-
-        #Adjust for OCTET STRING encapsulation
-        privateKeyP = ASN1Parser(privateKeyP.value)
-
-        return Python_RSAKey._parseASN1PrivateKey(privateKeyP)
-    _parsePKCS8 = staticmethod(_parsePKCS8)
-
-    def _parseSSLeay(bytes):
-        privateKeyP = ASN1Parser(bytes)
-        return Python_RSAKey._parseASN1PrivateKey(privateKeyP)
-    _parseSSLeay = staticmethod(_parseSSLeay)
-
-    def _parseASN1PrivateKey(privateKeyP):
-        version = privateKeyP.getChild(0).value[0]
-        if version != 0:
-            raise SyntaxError("Unrecognized RSAPrivateKey version")
-        n = bytesToNumber(privateKeyP.getChild(1).value)
-        e = bytesToNumber(privateKeyP.getChild(2).value)
-        d = bytesToNumber(privateKeyP.getChild(3).value)
-        p = bytesToNumber(privateKeyP.getChild(4).value)
-        q = bytesToNumber(privateKeyP.getChild(5).value)
-        dP = bytesToNumber(privateKeyP.getChild(6).value)
-        dQ = bytesToNumber(privateKeyP.getChild(7).value)
-        qInv = bytesToNumber(privateKeyP.getChild(8).value)
-        return Python_RSAKey(n, e, d, p, q, dP, dQ, qInv)
-    _parseASN1PrivateKey = staticmethod(_parseASN1PrivateKey)
+        from .python_key import Python_Key
+        return Python_Key.parsePEM(s, passwordCallback)
```
