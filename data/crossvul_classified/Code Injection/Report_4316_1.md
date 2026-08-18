# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in python
**Pair ID:** 4316_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4316_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```python
Lines 1-22 of the vulnerable file.

from __future__ import absolute_import
import datetime
import logging
import os
import socket
from socket import error as SocketError, timeout as SocketTimeout
import warnings
from .packages import six
from .packages.six.moves.http_client import HTTPConnection as _HTTPConnection
from .packages.six.moves.http_client import HTTPException  # noqa: F401

try:  # Compiled with SSL?
    import ssl

    BaseSSLError = ssl.SSLError
except (ImportError, AttributeError):  # Platform-specific: No SSL.
    ssl = None

    class BaseSSLError(BaseException):
        pass


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,5 @@
 from __future__ import absolute_import
+import re
 import datetime
 import logging
 import os
@@ -58,6 +59,8 @@
 # (ie test_recent_date is failing) update it to ~6 months before the current date.
 RECENT_DATE = datetime.date(2019, 1, 1)
 
+_CONTAINS_CONTROL_CHAR_RE = re.compile(r"[^-!#$%&'*+.^_`|~0-9a-zA-Z]")
+
 
 class DummyConnection(object):
     """Used to detect a failed ConnectionCls import."""
@@ -183,6 +186,17 @@
     def connect(self):
         conn = self._new_conn()
         self._prepare_conn(conn)
+
+    def putrequest(self, method, url, *args, **kwargs):
+        """Send a request to the server"""
+        match = _CONTAINS_CONTROL_CHAR_RE.search(method)
+        if match:
+            raise ValueError(
+                "Method cannot contain non-token characters %r (found at least %r)"
+                % (method, match.group())
+            )
+
+        return _HTTPConnection.putrequest(self, method, url, *args, **kwargs)
 
     def request_chunked(self, method, url, body=None, headers=None):
         """
```
