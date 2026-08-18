# CrossVul Fix Pair: Use of Insufficiently Random Values in python
**Pair ID:** 5563_1
**Vulnerability Class:** Use of Insufficiently Random Values
**CWE:** CWE-330
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5563_1`)

## Vulnerability Information & PoC

## Description
Use of Insufficiently Random Values - When product generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated, and use this guess to impersona...

## Vulnerable Code
```python
Lines 16-56 of the vulnerable file.

    md5_constructor = md5.new
import six
from pyrad import tools

# Packet codes
AccessRequest = 1
AccessAccept = 2
AccessReject = 3
AccountingRequest = 4
AccountingResponse = 5
AccessChallenge = 11
StatusServer = 12
StatusClient = 13
DisconnectRequest = 40
DisconnectACK = 41
DisconnectNAK = 42
CoARequest = 43
CoAACK = 44
CoANAK = 45

# Current ID
CurrentID = random.randrange(1, 255)


class PacketError(Exception):
    pass


class Packet(dict):
    """Packet acts like a standard python map to provide simple access
    to the RADIUS attributes. Since RADIUS allows for repeated
    attributes the value will always be a sequence. pyrad makes sure
    to preserve the ordering when encoding and decoding packets.

    There are two ways to use the map intereface: if attribute
    names are used pyrad take care of en-/decoding data. If
    the attribute type number (or a vendor ID/attribute type
    tuple for vendor attributes) is used you work with the
    raw data.

    Normally you will not use this class directly, but one of the
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,8 +33,11 @@
 CoAACK = 44
 CoANAK = 45
 
+# Use cryptographic-safe random generator as provided by the OS.
+random_generator = random.SystemRandom()
+
 # Current ID
-CurrentID = random.randrange(1, 255)
+CurrentID = random_generator.randrange(1, 255)
 
 
 class PacketError(Exception):
@@ -208,7 +211,7 @@
 
         data = []
         for i in range(16):
-            data.append(random.randrange(0, 256))
+            data.append(random_generator.randrange(0, 256))
         if six.PY3:
             return bytes(data)
         else:
@@ -223,7 +226,7 @@
         :rtype:  integer
 
         """
-        return random.randrange(0, 256)
+        return random_generator.randrange(0, 256)
 
     def ReplyPacket(self):
         """Create a ready-to-transmit authentication reply packet.
```
