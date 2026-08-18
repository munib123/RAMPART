# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in python
**Pair ID:** 4621_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4621_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```python
Lines 1-5 of the vulnerable file.

VERSION = (0, 9, '3a3')

__version__ = '.'.join(map(str, VERSION))

version = lambda: __version__
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-VERSION = (0, 9, '3a3')
+VERSION = (0, 9, '3b1')
 
 __version__ = '.'.join(map(str, VERSION))
 
```
