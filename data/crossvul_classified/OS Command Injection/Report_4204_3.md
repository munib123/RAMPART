# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in python
**Pair ID:** 4204_3
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4204_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```python
Lines 1-21 of the vulnerable file.

"""
Defines a calendar extension that overrides code block rendering if the
language type is calendar
"""


import datetime
import calendar
import urwid


from lookatme.exceptions import IgnoredByContrib


def render_code(token, body, stack, loop):
    lang = token["lang"] or ""
    if lang != "calendar":
        raise IgnoredByContrib()
    
    today = datetime.datetime.utcnow()
    return urwid.Text(calendar.month(today.year, today.month))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,6 +12,14 @@
 from lookatme.exceptions import IgnoredByContrib
 
 
+def user_warnings():
+    """No warnings exist for this extension. Anything you want to warn the
+    user about, such as security risks in processing untrusted markdown, should
+    go here.
+    """
+    return []
+
+
 def render_code(token, body, stack, loop):
     lang = token["lang"] or ""
     if lang != "calendar":
```
