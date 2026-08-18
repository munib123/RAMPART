# CrossVul Fix Pair: Origin Validation Error in python
**Pair ID:** 4367_9
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4367_9`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```python
Lines 1-13 of the vulnerable file.

# SPDX-License-Identifier: EUPL-1.2
# Copyright (C) 2019 - 2020 Dimpact
from decouple import Csv, config as _config, undefined


def config(option: str, default=undefined, *args, **kwargs):
    if "split" in kwargs:
        kwargs.pop("split")
        kwargs["cast"] = Csv()

    if default is not undefined and default is not None:
        kwargs.setdefault("cast", type(default))
    return _config(option, default=default, *args, **kwargs)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,6 +7,8 @@
     if "split" in kwargs:
         kwargs.pop("split")
         kwargs["cast"] = Csv()
+        if default == []:
+            default = ""
 
     if default is not undefined and default is not None:
         kwargs.setdefault("cast", type(default))
```
