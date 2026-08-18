# CrossVul Fix Pair: Inadequate Encryption Strength in python
**Pair ID:** 4376_1
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4376_1`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```python
Lines 6-46 of the vulnerable file.

from __future__ import division

from .compat import compatHMAC
import hmac

def ct_lt_u32(val_a, val_b):
    """
    Returns 1 if val_a < val_b, 0 otherwise. Constant time.

    :type val_a: int
    :type val_b: int
    :param val_a: an unsigned integer representable as a 32 bit value
    :param val_b: an unsigned integer representable as a 32 bit value
    :rtype: int
    """
    val_a &= 0xffffffff
    val_b &= 0xffffffff

    return (val_a^((val_a^val_b)|(((val_a-val_b)&0xffffffff)^val_b)))>>31

def ct_gt_u32(val_a, val_b):
    """
    Return 1 if val_a > val_b, 0 otherwise. Constant time.

    :type val_a: int
    :type val_b: int
    :param val_a: an unsigned integer representable as a 32 bit value
    :param val_b: an unsigned integer representable as a 32 bit value
    :rtype: int
    """
    return ct_lt_u32(val_b, val_a)

def ct_le_u32(val_a, val_b):
    """
    Return 1 if val_a <= val_b, 0 otherwise. Constant time.

    :type val_a: int
    :type val_b: int
    :param val_a: an unsigned integer representable as a 32 bit value
    :param val_b: an unsigned integer representable as a 32 bit value
    :rtype: int
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,6 +23,7 @@
 
     return (val_a^((val_a^val_b)|(((val_a-val_b)&0xffffffff)^val_b)))>>31
 
+
 def ct_gt_u32(val_a, val_b):
     """
     Return 1 if val_a > val_b, 0 otherwise. Constant time.
@@ -35,6 +36,7 @@
     """
     return ct_lt_u32(val_b, val_a)
 
+
 def ct_le_u32(val_a, val_b):
     """
     Return 1 if val_a <= val_b, 0 otherwise. Constant time.
@@ -47,14 +49,26 @@
     """
     return 1 ^ ct_gt_u32(val_a, val_b)
 
+
 def ct_lsb_prop_u8(val):
-    """Propagate LSB to all 8 bits of the returned byte. Constant time."""
+    """Propagate LSB to all 8 bits of the returned int. Constant time."""
     val &= 0x01
     val |= val << 1
     val |= val << 2
     val |= val << 4
     return val
 
+
+def ct_lsb_prop_u16(val):
+    """Propagate LSB to all 16 bits of the returned int. Constant time."""
+    val &= 0x01
+    val |= val << 1
+    val |= val << 2
+    val |= val << 4
+    val |= val << 8
+    return val
+
+
 def ct_isnonzero_u32(val):
     """
     Returns 1 if val is != 0, 0 otherwise. Constant time.
@@ -65,6 +79,7 @@
     """
     val &= 0xffffffff
     return (val|(-val&0xffffffff)) >> 31
+
 
 def ct_neq_u32(val_a, val_b):
     """
```
