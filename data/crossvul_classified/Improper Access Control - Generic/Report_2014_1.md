# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 2014_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2014_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 1-38 of the vulnerable file.

# -*- coding: utf-8 -*-
"""
    jinja2.bccache
    ~~~~~~~~~~~~~~

    This module implements the bytecode cache system Jinja is optionally
    using.  This is useful if you have very complex template situations and
    the compiliation of all those templates slow down your application too
    much.

    Situations where this is useful are often forking web applications that
    are initialized on the first request.

    :copyright: (c) 2010 by the Jinja Team.
    :license: BSD.
"""
from os import path, listdir
import sys
import marshal
import tempfile
import fnmatch
from hashlib import sha1
from jinja2.utils import open_if_exists
from jinja2._compat import BytesIO, pickle, PY2, text_type


# marshal works better on 3.x, one hack less required
if not PY2:
    marshal_dump = marshal.dump
    marshal_load = marshal.load
else:

    def marshal_dump(code, f):
        if isinstance(f, file):
            marshal.dump(code, f)
        else:
            f.write(marshal.dumps(code))

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,7 +15,9 @@
     :license: BSD.
 """
 from os import path, listdir
+import os
 import sys
+import errno
 import marshal
 import tempfile
 import fnmatch
@@ -189,7 +191,9 @@
     two arguments: The directory where the cache items are stored and a
     pattern string that is used to build the filename.
 
-    If no directory is specified the system temporary items folder is used.
+    If no directory is specified a default cache directory is selected.  On
+    Windows the user's temp directory is used, on UNIX systems a directory
+    is created for the user in the system temp directory.
 
     The pattern can be used to have multiple separate caches operate on the
     same directory.  The default pattern is ``'__jinja2_%s.cache'``.  ``%s``
@@ -202,9 +206,30 @@
 
     def __init__(self, directory=None, pattern='__jinja2_%s.cache'):
         if directory is None:
-            directory = tempfile.gettempdir()
+            directory = self._get_default_cache_dir()
         self.directory = directory
         self.pattern = pattern
+
+    def _get_default_cache_dir(self):
+        tmpdir = tempfile.gettempdir()
+
+        # On windows the temporary directory is used specific unless
+        # explicitly forced otherwise.  We can just use that.
+        if os.name == 'n':
+            return tmpdir
+        if not hasattr(os, 'getuid'):
+            raise RuntimeError('Cannot determine safe temp directory.  You '
+                               'need to explicitly provide one.')
+
+        dirname = '_jinja2-cache-%d' % os.getuid()
+        actual_dir = os.path.join(tmpdir, dirname)
+        try:
+            os.mkdir(actual_dir, 0700)
+        except OSError as e:
+            if e.errno != errno.EEXIST:
+                raise
+
+        return actual_dir
 
     def _get_cache_filename(self, bucket):
         return path.join(self.directory, self.pattern % bucket.key)
```
