# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in python
**Pair ID:** 1582_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1582_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```python
Lines 953-993 of the vulnerable file.

            recordHeader, b = self._handshakeBuffer[0]
            self._handshakeBuffer = self._handshakeBuffer[1:]
            yield (recordHeader, Parser(b))


    def _decryptRecord(self, recordType, b):
        if self._readState.encContext:

            #Decrypt if it's a block cipher
            if self._readState.encContext.isBlockCipher:
                blockLength = self._readState.encContext.block_size
                if len(b) % blockLength != 0:
                    for result in self._sendError(\
                            AlertDescription.decryption_failed,
                            "Encrypted data not a multiple of blocksize"):
                        yield result
                b = self._readState.encContext.decrypt(b)
                if self.version >= (3,2): #For TLS 1.1, remove explicit IV
                    b = b[self._readState.encContext.block_size : ]

                #Check padding
                paddingGood = True
                paddingLength = b[-1]
                if (paddingLength+1) > len(b):
                    paddingGood=False
                    totalPaddingLength = 0
                else:
                    if self.version == (3,0):
                        totalPaddingLength = paddingLength+1
                    elif self.version in ((3,1), (3,2), (3,3)):
                        totalPaddingLength = paddingLength+1
                        paddingBytes = b[-totalPaddingLength:-1]
                        for byte in paddingBytes:
                            if byte != paddingLength:
                                paddingGood = False
                                totalPaddingLength = 0
                    else:
                        raise AssertionError()

            #Decrypt if it's a stream cipher
            else:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -970,6 +970,12 @@
                 if self.version >= (3,2): #For TLS 1.1, remove explicit IV
                     b = b[self._readState.encContext.block_size : ]
 
+                if len(b) == 0:
+                    for result in self._sendError(\
+                            AlertDescription.decryption_failed,
+                            "No data left after decryption and IV removal"):
+                        yield result
+
                 #Check padding
                 paddingGood = True
                 paddingLength = b[-1]
```
