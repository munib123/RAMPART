# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in python
**Pair ID:** 4204_7
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4204_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```python
Lines 1-31 of the vulnerable file.

"""
This module handles loading and using lookatme_contriba modules

Contrib modules are directly used 
"""


import contextlib


from lookatme.exceptions import IgnoredByContrib
from . import terminal
from . import file_loader


CONTRIB_MODULES = [
    terminal,
    file_loader,
]


def load_contribs(contrib_names):
    """Load all contrib modules specified by ``contrib_names``. These should
    all be namespaced packages under the ``lookatmecontrib`` namespace. E.g.
    ``lookatmecontrib.calendar`` would be an extension provided by a
    contrib module, and would be added to an ``extensions`` list in a slide's
    YAML header as ``calendar``.
    """
    if contrib_names is None:
        return

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,40 +8,77 @@
 import contextlib
 
 
+import lookatme.ascii_art
 from lookatme.exceptions import IgnoredByContrib
+import lookatme.prompt
 from . import terminal
 from . import file_loader
 
 
-CONTRIB_MODULES = [
-    terminal,
-    file_loader,
-]
+CONTRIB_MODULES = []
 
 
-def load_contribs(contrib_names):
+def validate_extension_mod(ext_name, ext_mod):
+    """Validate the extension, returns an array of warnings associated with the
+    module
+    """
+    res = []
+    if not hasattr(ext_mod, "user_warnings"):
+        res.append("'user_warnings' is missing. Extension is not able to "
+                   "provide user warnings.")
+    else:
+        res += ext_mod.user_warnings()
+
+    return res
+
+
+def load_contribs(contrib_names, safe_contribs, ignore_load_failure=False):
     """Load all contrib modules specified by ``contrib_names``. These should
     all be namespaced packages under the ``lookatmecontrib`` namespace. E.g.
     ``lookatmecontrib.calendar`` would be an extension provided by a
     contrib module, and would be added to an ``extensions`` list in a slide's
     YAML header as ``calendar``.
+
+    ``safe_contribs`` is a set of contrib names that are manually provided
+    by the user by the ``-e`` flag or env variable of extensions to auto-load.
     """
     if contrib_names is None:
         return
 
     errors = []
+    all_warnings = []
     for contrib_name in contrib_names:
         module_name = f"lookatme.contrib.{contrib_name}"
         try:
             mod = __import__(module_name, fromlist=[contrib_name])
+        except Exception as e:
+            if ignore_load_failure:
+                continue
+            errors.append(str(e))
+        else:
+            if contrib_name not in safe_contribs:
+                ext_warnings = validate_extension_mod(contrib_name, mod)
+                if len(ext_warnings) > 0:
+                    all_warnings.append((contrib_name, ext_warnings))
             CONTRIB_MODULES.append(mod)
-        except Exception as e:
-            errors.append(str(e))
 
     if len(errors) > 0:
         raise Exception(
             "Error loading one or more extensions:\n\n" + "\n".join(errors),
         )
+
+    if len(all_warnings) == 0:
+        return
+
+    print("\nExtension-provided user warnings:")
+    for ext_name, ext_warnings in all_warnings:
+        print("\n  {!r}:\n".format(ext_name))
+        for ext_warning in ext_warnings:
+            print("    * {}".format(ext_warning))
+    print("")
+
+    if not lookatme.prompt.yes("Continue anyways?"):
+        exit(1)
 
 
 def contrib_first(fn):
```
