# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 872_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `872_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 30-70 of the vulnerable file.

from twisted.python.compat import _PY3, networkString
from twisted.python.compat import nativeString, intToBytes, unicode, itervalues
from twisted.python.deprecate import deprecatedModuleAttribute, deprecated
from twisted.python.failure import Failure
from incremental import Version

from twisted.web.iweb import IPolicyForHTTPS, IAgentEndpointFactory
from twisted.python.deprecate import getDeprecationWarningString
from twisted.web import http
from twisted.internet import defer, protocol, task, reactor
from twisted.internet.abstract import isIPv6Address
from twisted.internet.interfaces import IProtocol, IOpenSSLContextFactory
from twisted.internet.endpoints import HostnameEndpoint, wrapClientTLS
from twisted.python.util import InsensitiveDict
from twisted.python.components import proxyForInterface
from twisted.web import error
from twisted.web.iweb import UNKNOWN_LENGTH, IAgent, IBodyProducer, IResponse
from twisted.web.http_headers import Headers
from twisted.logger import Logger


class PartialDownloadError(error.Error):
    """
    Page was only partially downloaded, we got disconnected in middle.

    @ivar response: All of the response body which was downloaded.
    """


class HTTPPageGetter(http.HTTPClient):
    """
    Gets a resource via HTTP, then quits.

    Typically used with L{HTTPClientFactory}.  Note that this class does not, by
    itself, do anything with the response.  If you want to download a resource
    into a file, use L{HTTPPageDownloader} instead.

    @ivar _completelyDone: A boolean indicating whether any further requests are
        necessary after this one completes in order to provide a result to
        C{self.factory.deferred}.  If it is C{False}, then a redirect is going
        to be followed.  Otherwise, this protocol's connection is the last one
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,6 +47,9 @@
 from twisted.web.http_headers import Headers
 from twisted.logger import Logger
 
+from twisted.web._newclient import _ensureValidURI, _ensureValidMethod
+
+
 
 class PartialDownloadError(error.Error):
     """
@@ -78,11 +81,13 @@
 
     _completelyDone = True
 
-    _specialHeaders = set((b'host', b'user-agent', b'cookie', b'content-length'))
+    _specialHeaders = set(
+        (b'host', b'user-agent', b'cookie', b'content-length'),
+    )
 
     def connectionMade(self):
-        method = getattr(self.factory, 'method', b'GET')
-        self.sendCommand(method, self.factory.path)
+        method = _ensureValidMethod(getattr(self.factory, 'method', b'GET'))
+        self.sendCommand(method, _ensureValidURI(self.factory.path))
         if self.factory.scheme == b'http' and self.factory.port != 80:
             host = self.factory.host + b':' + intToBytes(self.factory.port)
         elif self.factory.scheme == b'https' and self.factory.port != 443:
@@ -362,7 +367,7 @@
             # just in case a broken http/1.1 decides to keep connection alive
             self.headers.setdefault(b"connection", b"close")
         self.postdata = postdata
-        self.method = method
+        self.method = _ensureValidMethod(method)
 
         self.setURL(url)
 
@@ -389,6 +394,7 @@
         return "<%s: %s>" % (self.__class__.__name__, self.url)
 
     def setURL(self, url):
+        _ensureValidURI(url.strip())
         self.url = url
         uri = URI.fromBytes(url)
         if uri.scheme and uri.host:
@@ -733,7 +739,7 @@
 
     @return: The factory created by C{factoryFactory}
     """
-    uri = URI.fromBytes(url)
+    uri = URI.fromBytes(_ensureValidURI(url.strip()))
     factory = factoryFactory(url, *args, **kwargs)
     if uri.scheme == b'https':
         from twisted.internet import ssl
@@ -1493,6 +1499,9 @@
         if not isinstance(method, bytes):
             raise TypeError('method={!r} is {}, but must be bytes'.format(
                     method, type(method)))
+
+        method = _ensureValidMethod(method)
+
         # Create minimal headers, if necessary:
         if headers is None:
             headers = Headers()
@@ -1717,6 +1726,7 @@
 
         @see: L{twisted.web.iweb.IAgent.request}
         """
+        uri = _ensureValidURI(uri.strip())
         parsedURI = URI.fromBytes(uri)
         try:
             endpoint = self._getEndpoint(parsedURI)
@@ -1750,6 +1760,8 @@
         """
         Issue a new request via the configured proxy.
         """
+        uri = _ensureValidURI(uri.strip())
+
         # Cache *all* connections under the same key, since we are only
         # connecting to a single destination, the proxy:
         key = ("http-proxy", self._proxyEndpoint)
```
