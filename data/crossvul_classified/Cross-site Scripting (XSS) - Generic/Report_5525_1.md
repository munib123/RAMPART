# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 5525_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5525_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 52-81 of the vulnerable file.

    __allow_access_to_unprotected_subobjects__ = True

    def __getitem__(self, module):
        mod = safe_builtins['__import__'](module)
        path = module.split('.')
        for name in path[1:]:
            mod = getattr(mod, name)
        return mod

from DocumentTemplate.DT_Util import TemplateDict, InstanceDict
from AccessControl.DTML import RestrictedDTML
class Rtd(RestrictedDTML, TemplateDict):
    this = None

def call_with_ns(f, ns, arg=1):
    td = Rtd()
    # prefer 'context' to 'here';  fall back to 'None'
    this = ns.get('context', ns.get('here'))
    td.this = this
    request = ns.get('request', {})
    td._push(request)
    td._push(InstanceDict(td.this, td))
    td._push(ns)
    try:
        if arg==2:
            return f(None, td)
        else:
            return f(td)
    finally:
        td._pop(3)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -69,6 +69,8 @@
     this = ns.get('context', ns.get('here'))
     td.this = this
     request = ns.get('request', {})
+    if hasattr(request, 'taintWrapper'):
+        request = request.taintWrapper()
     td._push(request)
     td._push(InstanceDict(td.this, td))
     td._push(ns)
```
