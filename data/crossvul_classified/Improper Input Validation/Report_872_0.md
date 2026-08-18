# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 872_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `872_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 11-51 of the vulnerable file.

  - Create a L{Request} with the appropriate data
  - Pass the request to L{HTTP11ClientProtocol.request}
  - The returned Deferred will fire with a L{Response} object
  - Create a L{IProtocol} provider which can handle the response body
  - Connect it to the response with L{Response.deliverBody}
  - When the protocol's C{connectionLost} method is called, the response is
    complete.  See L{Response.deliverBody} for details.

Various other classes in this module support this usage:

  - HTTPParser is the basic HTTP parser.  It can handle the parts of HTTP which
    are symmetric between requests and responses.

  - HTTPClientParser extends HTTPParser to handle response-specific parts of
    HTTP.  One instance is created for each request to parse the corresponding
    response.
"""

from __future__ import division, absolute_import
__metaclass__ = type

from zope.interface import implementer

from twisted.python.compat import networkString
from twisted.python.components import proxyForInterface
from twisted.python.reflect import fullyQualifiedName
from twisted.python.failure import Failure
from twisted.internet.interfaces import IConsumer, IPushProducer
from twisted.internet.error import ConnectionDone
from twisted.internet.defer import Deferred, succeed, fail, maybeDeferred
from twisted.internet.defer import CancelledError
from twisted.internet.protocol import Protocol
from twisted.protocols.basic import LineReceiver
from twisted.web.iweb import UNKNOWN_LENGTH, IResponse, IClientRequest
from twisted.web.http_headers import Headers
from twisted.web.http import NO_CONTENT, NOT_MODIFIED
from twisted.web.http import _DataLoss, PotentialDataLoss
from twisted.web.http import _IdentityTransferDecoder, _ChunkedTransferDecoder
from twisted.logger import Logger

# States HTTPParser can be in
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,8 @@
 
 from __future__ import division, absolute_import
 __metaclass__ = type
+
+import re
 
 from zope.interface import implementer
 
@@ -579,6 +581,74 @@
 
 
 
+_VALID_METHOD = re.compile(
+    br"\A[%s]+\Z" % (
+        bytes().join(
+            (
+                b"!", b"#", b"$", b"%", b"&", b"'", b"*",
+                b"+", b"-", b".", b"^", b"_", b"`", b"|", b"~",
+                b"\x30-\x39",
+                b"\x41-\x5a",
+                b"\x61-\x7A",
+            ),
+        ),
+    ),
+)
+
+
+
+def _ensureValidMethod(method):
+    """
+    An HTTP method is an HTTP token, which consists of any visible
+    ASCII character that is not a delimiter (i.e. one of
+    C{"(),/:;<=>?@[\\]{}}.)
+
+    @param method: the method to check
+    @type method: L{bytes}
+
+    @return: the method if it is valid
+    @rtype: L{bytes}
+
+    @raise ValueError: if the method is not valid
+
+    @see: U{https://tools.ietf.org/html/rfc7230#section-3.1.1},
+        U{https://tools.ietf.org/html/rfc7230#section-3.2.6},
+        U{https://tools.ietf.org/html/rfc5234#appendix-B.1}
+    """
+    if _VALID_METHOD.match(method):
+        return method
+    raise ValueError("Invalid method {!r}".format(method))
+
+
+
+_VALID_URI = re.compile(br'\A[\x21-\x7e]+\Z')
+
+
+
+def _ensureValidURI(uri):
+    """
+    A valid URI cannot contain control characters (i.e., characters
+    between 0-32, inclusive and 127) or non-ASCII characters (i.e.,
+    characters with values between 128-255, inclusive).
+
+    @param uri: the URI to check
+    @type uri: L{bytes}
+
+    @return: the URI if it is valid
+    @rtype: L{bytes}
+
+    @raise ValueError: if the URI is not valid
+
+    @see: U{https://tools.ietf.org/html/rfc3986#section-3.3},
+        U{https://tools.ietf.org/html/rfc3986#appendix-A},
+        U{https://tools.ietf.org/html/rfc5234#appendix-B.1}
+    """
+    if _VALID_URI.match(uri):
+        return uri
+    raise ValueError("Invalid URI {!r}".format(uri))
+
+
+
 @implementer(IClientRequest)
 class Request:
     """
@@ -618,8 +688,8 @@
             connection, defaults to C{False}.
         @type persistent: L{bool}
         """
-        self.method = method
-        self.uri = uri
+        self.method = _ensureValidMethod(method)
+        self.uri = _ensureValidURI(uri)
         self.headers = headers
         self.bodyProducer = bodyProducer
         self.persistent = persistent
@@ -664,8 +734,15 @@
         # method would probably be good.  It would be nice if this method
         # weren't limited to issuing HTTP/1.1 requests.
         requestLines = []
-        requestLines.append(b' '.join([self.method, self.uri,
-            b'HTTP/1.1\r\n']))
+        requestLines.append(
+            b' '.join(
+                [
+                    _ensureValidMethod(self.method),
+                    _ensureValidURI(self.uri),
+                    b'HTTP/1.1\r\n',
+                ]
+            ),
+        )
         if not self.persistent:
             requestLines.append(b'Connection: close\r\n')
         if TEorCL is not None:
```
