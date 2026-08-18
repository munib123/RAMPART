# CrossVul Fix Pair: Uncontrolled Resource Consumption in python
**Pair ID:** 1916_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1916_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```python
Lines 703-743 of the vulnerable file.

            and max_size
            and int(resp_headers[b"Content-Length"][0]) > max_size
        ):
            logger.warning("Requested URL is too large > %r bytes" % (max_size,))
            raise SynapseError(
                502,
                "Requested file is too large > %r bytes" % (max_size,),
                Codes.TOO_LARGE,
            )

        if response.code > 299:
            logger.warning("Got %d when downloading %s" % (response.code, url))
            raise SynapseError(502, "Got error %d" % (response.code,), Codes.UNKNOWN)

        # TODO: if our Content-Type is HTML or something, just read the first
        # N bytes into RAM rather than saving it all to disk only to read it
        # straight back in again

        try:
            length = await make_deferred_yieldable(
                readBodyToFile(response, output_stream, max_size)
            )
        except SynapseError:
            # This can happen e.g. because the body is too large.
            raise
        except Exception as e:
            raise SynapseError(502, ("Failed to download remote body: %s" % e)) from e

        return (
            length,
            resp_headers,
            response.request.absoluteURI.decode("ascii"),
            response.code,
        )


def _timeout_to_request_timed_out_error(f: Failure):
    if f.check(twisted_error.TimeoutError, twisted_error.ConnectingCancelledError):
        # The TCP connection has its own timeout (set by the 'connectTimeout' param
        # on the Agent), which raises twisted_error.TimeoutError exception.
        raise RequestTimedOutError("Timeout connecting to remote server")
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -720,11 +720,14 @@
 
         try:
             length = await make_deferred_yieldable(
-                readBodyToFile(response, output_stream, max_size)
+                read_body_with_max_size(response, output_stream, max_size)
             )
-        except SynapseError:
-            # This can happen e.g. because the body is too large.
-            raise
+        except BodyExceededMaxSize:
+            SynapseError(
+                502,
+                "Requested file is too large > %r bytes" % (max_size,),
+                Codes.TOO_LARGE,
+            )
         except Exception as e:
             raise SynapseError(502, ("Failed to download remote body: %s" % e)) from e
 
@@ -748,7 +751,11 @@
     return f
 
 
-class _ReadBodyToFileProtocol(protocol.Protocol):
+class BodyExceededMaxSize(Exception):
+    """The maximum allowed size of the HTTP body was exceeded."""
+
+
+class _ReadBodyWithMaxSizeProtocol(protocol.Protocol):
     def __init__(
         self, stream: BinaryIO, deferred: defer.Deferred, max_size: Optional[int]
     ):
@@ -761,13 +768,7 @@
         self.stream.write(data)
         self.length += len(data)
         if self.max_size is not None and self.length >= self.max_size:
-            self.deferred.errback(
-                SynapseError(
-                    502,
-                    "Requested file is too large > %r bytes" % (self.max_size,),
-                    Codes.TOO_LARGE,
-                )
-            )
+            self.deferred.errback(BodyExceededMaxSize())
             self.deferred = defer.Deferred()
             self.transport.loseConnection()
 
@@ -782,11 +783,14 @@
             self.deferred.errback(reason)
 
 
-def readBodyToFile(
+def read_body_with_max_size(
     response: IResponse, stream: BinaryIO, max_size: Optional[int]
 ) -> defer.Deferred:
     """
     Read a HTTP response body to a file-object. Optionally enforcing a maximum file size.
+
+    If the maximum file size is reached, the returned Deferred will resolve to a
+    Failure with a BodyExceededMaxSize exception.
 
     Args:
         response: The HTTP response to read from.
@@ -798,7 +802,7 @@
     """
 
     d = defer.Deferred()
-    response.deliverBody(_ReadBodyToFileProtocol(stream, d, max_size))
+    response.deliverBody(_ReadBodyWithMaxSizeProtocol(stream, d, max_size))
     return d
 
 
```
