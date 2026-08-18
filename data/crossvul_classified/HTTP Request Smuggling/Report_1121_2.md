# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in python
**Pair ID:** 1121_2
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1121_2`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```python
Lines 12-52 of the vulnerable file.

#
##############################################################################
"""HTTP Request Parser

This server uses asyncore to accept connections and do initial
processing but threads to do work.
"""
import re
from io import BytesIO

from waitress.buffers import OverflowableBuffer
from waitress.compat import tostr, unquote_bytes_to_wsgi, urlparse
from waitress.receiver import ChunkedReceiver, FixedStreamReceiver
from waitress.utilities import (
    BadRequest,
    RequestEntityTooLarge,
    RequestHeaderFieldsTooLarge,
    ServerNotImplemented,
    find_double_newline,
)


class ParsingError(Exception):
    pass


class TransferEncodingNotImplemented(Exception):
    pass


class HTTPRequestParser(object):
    """A structure that collects the HTTP request.

    Once the stream is completed, the instance is passed to
    a server task constructor.
    """

    completed = False  # Set once request is completed.
    empty = False  # Set if no request was made.
    expect_continue = False  # client sent "Expect: 100-continue" header
    headers_finished = False  # True when headers have been read
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,7 @@
     ServerNotImplemented,
     find_double_newline,
 )
+from .rfc7230 import HEADER_FIELD
 
 
 class ParsingError(Exception):
@@ -37,7 +38,6 @@
 
 class TransferEncodingNotImplemented(Exception):
     pass
-
 
 class HTTPRequestParser(object):
     """A structure that collects the HTTP request.
@@ -208,26 +208,27 @@
 
         headers = self.headers
         for line in lines:
-            index = line.find(b":")
-            if index > 0:
-                key = line[:index]
-
-                if key != key.strip():
-                    raise ParsingError("Invalid whitespace after field-name")
-
-                if b"_" in key:
-                    continue
-                value = line[index + 1 :].strip()
-                key1 = tostr(key.upper().replace(b"-", b"_"))
-                # If a header already exists, we append subsequent values
-                # seperated by a comma. Applications already need to handle
-                # the comma seperated values, as HTTP front ends might do
-                # the concatenation for you (behavior specified in RFC2616).
-                try:
-                    headers[key1] += tostr(b", " + value)
-                except KeyError:
-                    headers[key1] = tostr(value)
-            # else there's garbage in the headers?
+            header = HEADER_FIELD.match(line)
+
+            if not header:
+                raise ParsingError("Invalid header")
+
+            key, value = header.group('name', 'value')
+
+            if b"_" in key:
+                # TODO(xistence): Should we drop this request instead?
+                continue
+
+            value = value.strip()
+            key1 = tostr(key.upper().replace(b"-", b"_"))
+            # If a header already exists, we append subsequent values
+            # seperated by a comma. Applications already need to handle
+            # the comma seperated values, as HTTP front ends might do
+            # the concatenation for you (behavior specified in RFC2616).
+            try:
+                headers[key1] += tostr(b", " + value)
+            except KeyError:
+                headers[key1] = tostr(value)
 
         # command, uri, version will be bytes
         command, uri, version = crack_first_line(first_line)
@@ -352,6 +353,9 @@
     r = []
     lines = header.split(b"\r\n")
     for line in lines:
+        if not line:
+            continue
+
         if b"\r" in line or b"\n" in line:
             raise ParsingError('Bare CR or LF found in header line "%s"' % tostr(line))
 
```
