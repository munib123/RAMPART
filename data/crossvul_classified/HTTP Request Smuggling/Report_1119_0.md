# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in python
**Pair ID:** 1119_0
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1119_0`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```python
Lines 2-47 of the vulnerable file.

#
# Copyright (c) 2001, 2002 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""HTTP Request Parser

This server uses asyncore to accept connections and do initial
processing but threads to do work.
"""
import re
from io import BytesIO

from waitress.compat import (
    tostr,
    urlparse,
    unquote_bytes_to_wsgi,
)

from waitress.buffers import OverflowableBuffer

from waitress.receiver import (
    FixedStreamReceiver,
    ChunkedReceiver,
)

from waitress.utilities import (
    find_double_newline,
    RequestEntityTooLarge,
    RequestHeaderFieldsTooLarge,
    BadRequest,
)


class ParsingError(Exception):
    pass


class HTTPRequestParser(object):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,24 +19,14 @@
 import re
 from io import BytesIO
 
-from waitress.compat import (
-    tostr,
-    urlparse,
-    unquote_bytes_to_wsgi,
-)
-
 from waitress.buffers import OverflowableBuffer
-
-from waitress.receiver import (
-    FixedStreamReceiver,
-    ChunkedReceiver,
-)
-
+from waitress.compat import tostr, unquote_bytes_to_wsgi, urlparse
+from waitress.receiver import ChunkedReceiver, FixedStreamReceiver
 from waitress.utilities import (
-    find_double_newline,
+    BadRequest,
     RequestEntityTooLarge,
     RequestHeaderFieldsTooLarge,
-    BadRequest,
+    find_double_newline,
 )
 
 
@@ -95,8 +85,13 @@
                 # Header finished.
                 header_plus = s[:index]
                 consumed = len(data) - (len(s) - index)
-                # Remove preceeding blank lines.
+
+                # Remove preceeding blank lines. This is suggested by
+                # https://tools.ietf.org/html/rfc7230#section-3.5 to support
+                # clients sending an extra CR LF after another request when
+                # using HTTP pipelining
                 header_plus = header_plus.lstrip()
+
                 if not header_plus:
                     self.empty = True
                     self.completed = True
@@ -169,13 +164,15 @@
         Parses the header_plus block of text (the headers plus the
         first line of the request).
         """
-        index = header_plus.find(b"\n")
+        index = header_plus.find(b"\r\n")
         if index >= 0:
             first_line = header_plus[:index].rstrip()
-            header = header_plus[index + 1 :]
-        else:
-            first_line = header_plus.rstrip()
-            header = b""
+            header = header_plus[index + 2 :]
+        else:
+            raise ParsingError("HTTP message header invalid")
+
+        if b"\r" in first_line or b"\n" in first_line:
+            raise ParsingError("Bare CR or LF found in HTTP message")
 
         self.first_line = first_line  # for testing
 
@@ -299,8 +296,11 @@
     Splits the header into lines, putting multi-line headers together.
     """
     r = []
-    lines = header.split(b"\n")
+    lines = header.split(b"\r\n")
     for line in lines:
+        if b"\r" in line or b"\n" in line:
+            raise ParsingError('Bare CR or LF found in header line "%s"' % tostr(line))
+
         if line.startswith((b" ", b"\t")):
             if not r:
                 # https://corte.si/posts/code/pathod/pythonservers/index.html
```
