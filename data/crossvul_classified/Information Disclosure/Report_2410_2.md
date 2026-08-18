# CrossVul Fix Pair: Observable Discrepancy in python
**Pair ID:** 2410_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-203
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2410_2`)

## Vulnerability Information & PoC

## Description
Observable Discrepancy - Discrepancies can take many forms, and variations may be detectable in timing, control flow, communications such as replies or requests, or general behavior.

## Vulnerable Code
```python
Lines 1-35 of the vulnerable file.

"""Miscellaneous utility functions and classes.

This module is used internally by Tornado.  It is not necessarily expected
that the functions and classes defined here will be useful to other
applications, but they are documented here in case they are.

The one public-facing part of this module is the `Configurable` class
and its `~Configurable.configure` method, which becomes a part of the
interface of its subclasses, including `.AsyncHTTPClient`, `.IOLoop`,
and `.Resolver`.
"""

from __future__ import absolute_import, division, print_function, with_statement

import inspect
import sys
import zlib


class ObjectDict(dict):
    """Makes a dictionary behave like an object, with attribute-style access.
    """
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        self[name] = value


class GzipDecompressor(object):
    """Streaming gzip decompressor.

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,9 +12,17 @@
 
 from __future__ import absolute_import, division, print_function, with_statement
 
+import array
 import inspect
+import os
 import sys
 import zlib
+
+
+try:
+    xrange  # py2
+except NameError:
+    xrange = range  # py3
 
 
 class ObjectDict(dict):
@@ -265,6 +273,41 @@
         return old_value, args, kwargs
 
 
+def _websocket_mask_python(mask, data):
+    """Websocket masking function.
+
+    `mask` is a `bytes` object of length 4; `data` is a `bytes` object of any length.
+    Returns a `bytes` object of the same length as `data` with the mask applied
+    as specified in section 5.3 of RFC 6455.
+
+    This pure-python implementation may be replaced by an optimized version when available.
+    """
+    mask = array.array("B", mask)
+    unmasked = array.array("B", data)
+    for i in xrange(len(data)):
+        unmasked[i] = unmasked[i] ^ mask[i % 4]
+    if hasattr(unmasked, 'tobytes'):
+        # tostring was deprecated in py32.  It hasn't been removed,
+        # but since we turn on deprecation warnings in our tests
+        # we need to use the right one.
+        return unmasked.tobytes()
+    else:
+        return unmasked.tostring()
+
+if (os.environ.get('TORNADO_NO_EXTENSION') or
+    os.environ.get('TORNADO_EXTENSION') == '0'):
+    # These environment variables exist to make it easier to do performance
+    # comparisons; they are not guaranteed to remain supported in the future.
+    _websocket_mask = _websocket_mask_python
+else:
+    try:
+        from tornado.speedups import websocket_mask as _websocket_mask
+    except ImportError:
+        if os.environ.get('TORNADO_EXTENSION') == '1':
+            raise
+        _websocket_mask = _websocket_mask_python
+
+
 def doctests():
     import doctest
     return doctest.DocTestSuite()
```
