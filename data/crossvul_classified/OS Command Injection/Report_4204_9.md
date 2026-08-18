# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in python
**Pair ID:** 4204_9
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4204_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```python
Lines 1-39 of the vulnerable file.

"""
This module defines a built-in contrib module that enables terminal embedding
within a slide.
"""


from marshmallow import fields, Schema
import os
import re
import shlex
import signal
import urwid
import yaml


import lookatme.render
from lookatme.exceptions import IgnoredByContrib
import lookatme.config


class YamlRender:
    loads = lambda data: yaml.safe_load(data)
    dumps = lambda data: yaml.safe_dump(data)


class TerminalExSchema(Schema):
    """The schema used for ``terminal-ex`` code blocks.
    """
    command = fields.Str()
    rows = fields.Int(default=10, missing=10)
    init_text = fields.Str(default=None, missing=None)
    init_wait = fields.Str(default=None, missing=None)
    init_codeblock = fields.Bool(default=True, missing=True)
    init_codeblock_lang = fields.Str(default="text", missing="text")

    class Meta:
        render_module = YamlRender


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,6 +16,18 @@
 import lookatme.render
 from lookatme.exceptions import IgnoredByContrib
 import lookatme.config
+
+
+def user_warnings():
+    """Provide warnings to the user that loading this extension may cause
+    shell commands specified in the markdown to be run.
+    """
+    return [
+        "Code-blocks with a language starting with 'terminal' will cause shell",
+        "  commands from the source markdown to be run",
+        "See https://lookatme.readthedocs.io/en/latest/builtin_extensions/terminal.html",
+        "  for more details",
+    ]
 
 
 class YamlRender:
```
