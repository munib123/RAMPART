# CrossVul Fix Pair: Insertion of Sensitive Information into Log File in python
**Pair ID:** 18_0
**Vulnerability Class:** Insertion of Sensitive Information into Log File
**CWE:** CWE-532
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `18_0`)

## Vulnerability Information & PoC

## Description
Insertion of Sensitive Information into Log File - While logging all information may be helpful during development stages, it is important that logging levels be set appropriately before a product ships so that sensitive user data and system inform...

## Vulnerable Code
```python
Lines 1-9 of the vulnerable file.

from django.apps import AppConfig


class AnymailBaseConfig(AppConfig):
    name = 'anymail'
    verbose_name = "Anymail"

    def ready(self):
        pass
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,7 @@
 from django.apps import AppConfig
+from django.core import checks
+
+from .checks import check_deprecated_settings
 
 
 class AnymailBaseConfig(AppConfig):
@@ -6,4 +9,4 @@
     verbose_name = "Anymail"
 
     def ready(self):
-        pass
+        checks.register(check_deprecated_settings)
```
