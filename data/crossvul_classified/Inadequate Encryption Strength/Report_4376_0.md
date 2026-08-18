# CrossVul Fix Pair: Inadequate Encryption Strength in python
**Pair ID:** 4376_0
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4376_0`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```python
Lines 1-28 of the vulnerable file.

# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""Miscellaneous functions to mask Python version differences."""

import sys
import os
import platform
import math
import binascii
import traceback
import ecdsa

if sys.version_info >= (3,0):

    def compat26Str(x): return x
    
    # Python 3 requires bytes instead of bytearrays for HMAC   
    
    # So, python 2.6 requires strings, python 3 requires 'bytes',
    # and python 2.7 can handle bytearrays...     
    def compatHMAC(x): return bytes(x)

    def compatAscii2Bytes(val):
        """Convert ASCII string to bytes."""
        if isinstance(val, str):
            return bytes(val, 'ascii')
        return val
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,7 @@
 
 import sys
 import os
+import re
 import platform
 import math
 import binascii
@@ -68,6 +69,10 @@
         """Return exception information formatted as string"""
         return str(e)
 
+    def remove_whitespace(text):
+        """Removes all whitespace from passed in string"""
+        return re.sub(r"\s+", "", text, flags=re.UNICODE)
+
 else:
     # Python 2.6 requires strings instead of bytearrays in a couple places,
     # so we define this function so it does the conversion if needed.
@@ -76,8 +81,17 @@
     if sys.version_info < (2, 7) or sys.version_info < (2, 7, 4) \
             or platform.system() == 'Java':
         def compat26Str(x): return str(x)
+
+        def remove_whitespace(text):
+            """Removes all whitespace from passed in string"""
+            return re.sub(r"\s+", "", text)
+
     else:
         def compat26Str(x): return x
+
+        def remove_whitespace(text):
+            """Removes all whitespace from passed in string"""
+            return re.sub(r"\s+", "", text, flags=re.UNICODE)
 
     def compatAscii2Bytes(val):
         """Convert ASCII string to bytes."""
```
