# CrossVul Fix Pair: Improper Certificate Validation in python
**Pair ID:** 4414_1
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4414_1`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```python
Lines 1-3 of the vulnerable file.

VERSION = (0, 0, 52)

__version__ = '.'.join(map(str, VERSION))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,3 @@
-VERSION = (0, 0, 52)
+VERSION = (0, 0, 53)
 
 __version__ = '.'.join(map(str, VERSION))
```
