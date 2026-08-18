# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in python
**Pair ID:** 1119_1
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1119_1`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```python
Lines 1-39 of the vulnerable file.

##############################################################################
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
"""Data Chunk Receiver
"""

from waitress.utilities import find_double_newline

from waitress.utilities import BadRequest


class FixedStreamReceiver(object):

    # See IStreamConsumer
    completed = False
    error = None

    def __init__(self, cl, buf):
        self.remain = cl
        self.buf = buf

    def __len__(self):
        return self.buf.__len__()

    def received(self, data):
        "See IStreamConsumer"
        rm = self.remain
        if rm < 1:
            self.completed = True  # Avoid any chance of spinning
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,9 +14,7 @@
 """Data Chunk Receiver
 """
 
-from waitress.utilities import find_double_newline
-
-from waitress.utilities import BadRequest
+from waitress.utilities import BadRequest, find_double_newline
 
 
 class FixedStreamReceiver(object):
@@ -35,18 +33,23 @@
     def received(self, data):
         "See IStreamConsumer"
         rm = self.remain
+
         if rm < 1:
             self.completed = True  # Avoid any chance of spinning
+
             return 0
         datalen = len(data)
+
         if rm <= datalen:
             self.buf.append(data[:rm])
             self.remain = 0
             self.completed = True
+
             return rm
         else:
             self.buf.append(data)
             self.remain -= datalen
+
             return datalen
 
     def getfile(self):
@@ -59,6 +62,7 @@
 class ChunkedReceiver(object):
 
     chunk_remainder = 0
+    validate_chunk_end = False
     control_line = b""
     all_chunks_received = False
     trailer = b""
@@ -76,22 +80,42 @@
 
     def received(self, s):
         # Returns the number of bytes consumed.
+
         if self.completed:
             return 0
         orig_size = len(s)
+
         while s:
             rm = self.chunk_remainder
+
             if rm > 0:
                 # Receive the remainder of a chunk.
                 to_write = s[:rm]
                 self.buf.append(to_write)
                 written = len(to_write)
                 s = s[written:]
+
                 self.chunk_remainder -= written
+
+                if self.chunk_remainder == 0:
+                    self.validate_chunk_end = True
+            elif self.validate_chunk_end:
+                pos = s.find(b"\r\n")
+
+                if pos == 0:
+                    # Chop off the terminating CR LF from the chunk
+                    s = s[2:]
+                else:
+                    self.error = BadRequest("Chunk not properly terminated")
+                    self.all_chunks_received = True
+
+                # Always exit this loop
+                self.validate_chunk_end = False
             elif not self.all_chunks_received:
                 # Receive a control line.
                 s = self.control_line + s
-                pos = s.find(b"\n")
+                pos = s.find(b"\r\n")
+
                 if pos < 0:
                     # Control line not finished.
                     self.control_line = s
@@ -99,12 +123,14 @@
                 else:
                     # Control line finished.
                     line = s[:pos]
-                    s = s[pos + 1 :]
+                    s = s[pos + 2 :]
                     self.control_line = b""
                     line = line.strip()
+
                     if line:
                         # Begin a new chunk.
                         semi = line.find(b";")
+
                         if semi >= 0:
                             # discard extension info.
                             line = line[:semi]
@@ -113,6 +139,7 @@
                         except ValueError:  # garbage in input
                             self.error = BadRequest("garbage in chunked encoding input")
                             sz = 0
+
                         if sz > 0:
                             # Start a new chunk.
                             self.chunk_remainder = sz
@@ -123,15 +150,14 @@
             else:
                 # Receive the trailer.
                 trailer = self.trailer + s
+
                 if trailer.startswith(b"\r\n"):
                     # No trailer.
                     self.completed = True
+
                     return orig_size - (len(trailer) - 2)
-                elif trailer.startswith(b"\n"):
-                    # No trailer.
-                    self.completed = True
-                    return orig_size - (len(trailer) - 1)
                 pos = find_double_newline(trailer)
+
                 if pos < 0:
                     # Trailer not finished.
                     self.trailer = trailer
@@ -140,7 +166,9 @@
                     # Finished the trailer.
                     self.completed = True
                     self.trailer = trailer[:pos]
+
                     return orig_size - (len(trailer) - pos)
+
         return orig_size
 
     def getfile(self):
```
