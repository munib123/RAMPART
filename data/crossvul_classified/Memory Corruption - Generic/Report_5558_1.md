# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in python
**Pair ID:** 5558_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5558_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```python
Lines 294-313 of the vulnerable file.

    return hash_.hexdigest()


def setup_remote_pydev_debug():
    if CONF.pydev_debug_host and CONF.pydev_debug_port:
        error_msg = ('Error setting up the debug environment.  Verify that the'
                     ' option --debug-url has the format <host>:<port> and '
                     'that a debugger processes is listening on that port.')

        try:
            from pydev import pydevd

            pydevd.settrace(CONF.pydev_debug_host,
                            port=CONF.pydev_debug_port,
                            stdoutToServer=True,
                            stderrToServer=True)
            return True
        except:
            LOG.exception(_(error_msg))
            raise
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -311,3 +311,37 @@
         except:
             LOG.exception(_(error_msg))
             raise
+
+
+class LimitingReader(object):
+    """Reader to limit the size of an incoming request."""
+    def __init__(self, data, limit):
+        """
+        :param data: Underlying data object
+        :param limit: maximum number of bytes the reader should allow
+        """
+        self.data = data
+        self.limit = limit
+        self.bytes_read = 0
+
+    def __iter__(self):
+        for chunk in self.data:
+            self.bytes_read += len(chunk)
+            if self.bytes_read > self.limit:
+                raise exception.RequestTooLarge()
+            else:
+                yield chunk
+
+    def read(self, i):
+        result = self.data.read(i)
+        self.bytes_read += len(result)
+        if self.bytes_read > self.limit:
+            raise exception.RequestTooLarge()
+        return result
+
+    def read(self):
+        result = self.data.read()
+        self.bytes_read += len(result)
+        if self.bytes_read > self.limit:
+            raise exception.RequestTooLarge()
+        return result
```
