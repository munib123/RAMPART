# CrossVul Fix Pair: Observable Discrepancy in python
**Pair ID:** 2410_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-203
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2410_3`)

## Vulnerability Information & PoC

## Description
Observable Discrepancy - Discrepancies can take many forms, and variations may be detectable in timing, control flow, communications such as replies or requests, or general behavior.

## Vulnerable Code
```python
Lines 55-95 of the vulnerable file.


import base64
import binascii
import datetime
import email.utils
import functools
import gzip
import hashlib
import hmac
import mimetypes
import numbers
import os.path
import re
import stat
import sys
import threading
import time
import tornado
import traceback
import types
import uuid

from tornado.concurrent import Future
from tornado import escape
from tornado import httputil
from tornado import locale
from tornado.log import access_log, app_log, gen_log
from tornado import stack_context
from tornado import template
from tornado.escape import utf8, _unicode
from tornado.util import bytes_type, import_object, ObjectDict, raise_exc_info, unicode_type

try:
    from io import BytesIO  # python 3
except ImportError:
    from cStringIO import StringIO as BytesIO  # python 2

try:
    import Cookie  # py2
except ImportError:
    import http.cookies as Cookie  # py3
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,7 +72,6 @@
 import tornado
 import traceback
 import types
-import uuid
 
 from tornado.concurrent import Future
 from tornado import escape
@@ -82,7 +81,7 @@
 from tornado import stack_context
 from tornado import template
 from tornado.escape import utf8, _unicode
-from tornado.util import bytes_type, import_object, ObjectDict, raise_exc_info, unicode_type
+from tornado.util import bytes_type, import_object, ObjectDict, raise_exc_info, unicode_type, _websocket_mask
 
 try:
     from io import BytesIO  # python 3
@@ -1071,13 +1070,55 @@
         See http://en.wikipedia.org/wiki/Cross-site_request_forgery
         """
         if not hasattr(self, "_xsrf_token"):
-            token = self.get_cookie("_xsrf")
-            if not token:
-                token = binascii.b2a_hex(os.urandom(16))
+            version, token, timestamp = self._get_raw_xsrf_token()
+            mask = os.urandom(4)
+            self._xsrf_token = b"|".join([
+                b"2",
+                binascii.b2a_hex(mask),
+                binascii.b2a_hex(_websocket_mask(mask, token)),
+                utf8(str(int(timestamp)))])
+            if version is None or version != 2:
                 expires_days = 30 if self.current_user else None
-                self.set_cookie("_xsrf", token, expires_days=expires_days)
-            self._xsrf_token = token
+                self.set_cookie("_xsrf", self._xsrf_token,
+                                expires_days=expires_days)
         return self._xsrf_token
+
+    def _get_raw_xsrf_token(self):
+        if not hasattr(self, '_raw_xsrf_token'):
+            cookie = self.get_cookie("_xsrf")
+            if cookie:
+                version, token, timestamp = self._decode_xsrf_token(cookie)
+            else:
+                version, token, timestamp = None, None, None
+            if token is None:
+                version = None
+                token = os.urandom(16)
+                timestamp = time.time()
+            self._raw_xsrf_token = (version, token, timestamp)
+        return self._raw_xsrf_token
+
+    def _decode_xsrf_token(self, cookie):
+        m = _signed_value_version_re.match(utf8(cookie))
+        if m:
+            version = int(m.group(1))
+            if version == 2:
+                _, mask, masked_token, timestamp = cookie.split("|")
+                mask = binascii.a2b_hex(utf8(mask))
+                token = _websocket_mask(
+                    mask, binascii.a2b_hex(utf8(masked_token)))
+                timestamp = int(timestamp)
+                return version, token, timestamp
+            else:
+                # Treat unknown versions as not present instead of failing.
+                return None, None, None
+        elif len(cookie) == 32:
+            version = 1
+            token = binascii.a2b_hex(cookie)
+            # We don't have a usable timestamp in older versions.
+            timestamp = int(time.time())
+            return (version, token, timestamp)
+        else:
+            return None, None, None
 
     def check_xsrf_cookie(self):
         """Verifies that the ``_xsrf`` cookie matches the ``_xsrf`` argument.
@@ -1105,7 +1146,9 @@
                  self.request.headers.get("X-Csrftoken"))
         if not token:
             raise HTTPError(403, "'_xsrf' argument missing from POST")
-        if not _time_independent_equals(utf8(self.xsrf_token), utf8(token)):
+        _, token, _ = self._decode_xsrf_token(token)
+        _, expected_token, _ = self._get_raw_xsrf_token()
+        if not _time_independent_equals(utf8(token), utf8(expected_token)):
             raise HTTPError(403, "XSRF cookie does not match POST argument")
 
     def xsrf_form_html(self):
```
