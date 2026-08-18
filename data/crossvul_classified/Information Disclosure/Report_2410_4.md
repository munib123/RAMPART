# CrossVul Fix Pair: Observable Discrepancy in python
**Pair ID:** 2410_4
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-203
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2410_4`)

## Vulnerability Information & PoC

## Description
Observable Discrepancy - Discrepancies can take many forms, and variations may be detectable in timing, control flow, communications such as replies or requests, or general behavior.

## Vulnerable Code
```python
Lines 3-43 of the vulnerable file.

`WebSockets <http://dev.w3.org/html5/websockets/>`_ allow for bidirectional
communication between the browser and server.

.. warning::

   The WebSocket protocol was recently finalized as `RFC 6455
   <http://tools.ietf.org/html/rfc6455>`_ and is not yet supported in
   all browsers.  Refer to http://caniuse.com/websockets for details
   on compatibility.  In addition, during development the protocol
   went through several incompatible versions, and some browsers only
   support older versions.  By default this module only supports the
   latest version of the protocol, but optional support for an older
   version (known as "draft 76" or "hixie-76") can be enabled by
   overriding `WebSocketHandler.allow_draft76` (see that method's
   documentation for caveats).
"""

from __future__ import absolute_import, division, print_function, with_statement
# Author: Jacob Kristhammar, 2010

import array
import base64
import collections
import functools
import hashlib
import os
import struct
import time
import tornado.escape
import tornado.web

from tornado.concurrent import TracebackFuture
from tornado.escape import utf8, native_str
from tornado import httpclient, httputil
from tornado.ioloop import IOLoop
from tornado.iostream import StreamClosedError
from tornado.log import gen_log, app_log
from tornado.netutil import Resolver
from tornado import simple_httpclient
from tornado.util import bytes_type, unicode_type

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,7 +20,6 @@
 from __future__ import absolute_import, division, print_function, with_statement
 # Author: Jacob Kristhammar, 2010
 
-import array
 import base64
 import collections
 import functools
@@ -39,12 +38,7 @@
 from tornado.log import gen_log, app_log
 from tornado.netutil import Resolver
 from tornado import simple_httpclient
-from tornado.util import bytes_type, unicode_type
-
-try:
-    xrange  # py2
-except NameError:
-    xrange = range  # py3
+from tornado.util import bytes_type, unicode_type, _websocket_mask
 
 
 class WebSocketError(Exception):
@@ -890,38 +884,3 @@
     if callback is not None:
         io_loop.add_future(conn.connect_future, callback)
     return conn.connect_future
-
-
-def _websocket_mask_python(mask, data):
-    """Websocket masking function.
-
-    `mask` is a `bytes` object of length 4; `data` is a `bytes` object of any length.
-    Returns a `bytes` object of the same length as `data` with the mask applied
-    as specified in section 5.3 of RFC 6455.
-
-    This pure-python implementation may be replaced by an optimized version when available.
-    """
-    mask = array.array("B", mask)
-    unmasked = array.array("B", data)
-    for i in xrange(len(data)):
-        unmasked[i] = unmasked[i] ^ mask[i % 4]
-    if hasattr(unmasked, 'tobytes'):
-        # tostring was deprecated in py32.  It hasn't been removed,
-        # but since we turn on deprecation warnings in our tests
-        # we need to use the right one.
-        return unmasked.tobytes()
-    else:
-        return unmasked.tostring()
-
-if (os.environ.get('TORNADO_NO_EXTENSION') or
-    os.environ.get('TORNADO_EXTENSION') == '0'):
-    # These environment variables exist to make it easier to do performance
-    # comparisons; they are not guaranteed to remain supported in the future.
-    _websocket_mask = _websocket_mask_python
-else:
-    try:
-        from tornado.speedups import websocket_mask as _websocket_mask
-    except ImportError:
-        if os.environ.get('TORNADO_EXTENSION') == '1':
-            raise
-        _websocket_mask = _websocket_mask_python
```
