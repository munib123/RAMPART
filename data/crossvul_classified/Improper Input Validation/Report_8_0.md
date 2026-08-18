# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 8_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `8_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 1-37 of the vulnerable file.

from importlib import import_module
from os import path, listdir
from string import lower

from debug import logger
import paths

class MsgBase(object):
    def encode(self):
        self.data = {"": lower(type(self).__name__)}


def constructObject(data):
    try:
        classBase = eval(data[""] + "." + data[""].title())
    except NameError:
        logger.error("Don't know how to handle message type: \"%s\"", data[""])
        return None
    try:
        returnObj = classBase()
        returnObj.decode(data)
    except KeyError as e:
        logger.error("Missing mandatory key %s", e)
        return None
    except:
        logger.error("classBase fail", exc_info=True)
        return None
    else:
        return returnObj

if paths.frozen is not None:
    import messagetypes.message
    import messagetypes.vote
else:
    for mod in listdir(path.dirname(__file__)):
        if mod == "__init__.py":
            continue
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,9 +12,10 @@
 
 def constructObject(data):
     try:
-        classBase = eval(data[""] + "." + data[""].title())
-    except NameError:
-        logger.error("Don't know how to handle message type: \"%s\"", data[""])
+        m = import_module("messagetypes." + data[""])
+        classBase = getattr(m, data[""].title())
+    except (NameError, ImportError):
+        logger.error("Don't know how to handle message type: \"%s\"", data[""], exc_info=True)
         return None
     try:
         returnObj = classBase()
```
