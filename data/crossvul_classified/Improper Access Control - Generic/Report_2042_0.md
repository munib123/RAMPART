# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 2042_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2042_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 1-6 of the vulnerable file.

from django.core.exceptions import SuspiciousOperation


class DisallowedModelAdminLookup(SuspiciousOperation):
    """Invalid filter was passed to admin view via URL querystring"""
    pass
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,3 +4,8 @@
 class DisallowedModelAdminLookup(SuspiciousOperation):
     """Invalid filter was passed to admin view via URL querystring"""
     pass
+
+
+class DisallowedModelAdminToField(SuspiciousOperation):
+    """Invalid to_field was passed to admin view via URL query string"""
+    pass
```
