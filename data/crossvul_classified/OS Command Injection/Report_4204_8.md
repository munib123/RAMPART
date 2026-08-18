# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in python
**Pair ID:** 4204_8
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4204_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```python
Lines 1-37 of the vulnerable file.

"""
This module defines a built-in contrib module that enables external files to
be included within the slide. This is extremely useful when having source
code displayed in a code block, and then running/doing something with the
source data in a terminal on the same slide.
"""


from marshmallow import fields, Schema
import os
import subprocess
import yaml


import lookatme.config
from lookatme.exceptions import IgnoredByContrib


class YamlRender:
    loads = lambda data: yaml.safe_load(data)
    dumps = lambda data: yaml.safe_dump(data)


class LineRange(Schema):
    start = fields.Integer(default=0, missing=0)
    end = fields.Integer(default=None, missing=None)


class FileSchema(Schema):
    path = fields.Str()
    relative = fields.Boolean(default=True, missing=True)
    lang = fields.Str(default="auto", missing="auto")
    transform = fields.Str(default=None, missing=None)
    lines = fields.Nested(
        LineRange,
        default=LineRange().dump(LineRange()),
        missing=LineRange().dump(LineRange()),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,6 +14,19 @@
 
 import lookatme.config
 from lookatme.exceptions import IgnoredByContrib
+
+
+def user_warnings():
+    """Provide warnings to the user that loading this extension may cause
+    shell commands specified in the markdown to be run.
+    """
+    return [
+        "Code-blocks with a language starting with 'file' may cause shell",
+        "  commands from the source markdown to be run if the 'transform'",
+        "  field is set",
+        "See https://lookatme.readthedocs.io/en/latest/builtin_extensions/file_loader.html",
+        "  for more details",
+    ]
 
 
 class YamlRender:
```
