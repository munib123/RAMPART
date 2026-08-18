# CrossVul Fix Pair: Improper Privilege Management in python
**Pair ID:** 5731_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5731_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```python
Lines 17-57 of the vulnerable file.

    could be compiled for different types for 'a' (although not likely in
    this case). The catalog first looks in its cache and quickly returns
    a list of the functions if possible.  If the cache lookup fails, it then
    looks through possibly multiple catalog files on disk and fills its
    cache with all the functions that match the code fragment.

    In case where the code fragment hasn't been compiled, inline() compiles
    the code and then adds it to the catalog:

        function = <code to compile function>
        catalog.add_function('printf("printed from C: %d", a);',function)

    add_function() adds function to the front of the cache.  function,
    along with the path information to its module, are also stored in a
    persistent catalog for future use by python sessions.
"""
from __future__ import absolute_import, print_function

import os
import sys
import pickle
import socket
import tempfile

try:
    import dbhash
    import shelve
    dumb = 0
except ImportError:
    from . import _dumb_shelve as shelve
    dumb = 1

#For testing...
#import scipy.io.dumb_shelve as shelve
#dumb = 1

#import shelve
#dumb = 0

def getmodule(object):
    """ Discover the name of the module where object was defined.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,6 +34,7 @@
 
 import os
 import sys
+import stat
 import pickle
 import socket
 import tempfile
@@ -133,7 +134,7 @@
 
     # Do NOT use a hardcoded name here due to the danger from race conditions
     # on NFS when multiple processes are accessing the same base directory in
-    # parallel.  We use both hostname and pocess id for the prefix in an
+    # parallel.  We use both hostname and process id for the prefix in an
     # attempt to ensure that there can really be no name collisions (tempfile
     # appends 6 random chars to this prefix).
     prefix = 'dummy_%s_%s_' % (socket.gethostname(),os.getpid())
@@ -150,6 +151,88 @@
     """return a string identifying the user."""
     return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
 
+
+def _create_dirs(path):
+    """ create provided path, ignore errors """
+    try:
+        os.makedirs(path, mode=0o700)
+    except OSError:
+        pass
+
+
+def default_dir_posix(tmp_dir=None):
+    """
+    Create or find default catalog store for posix systems
+
+    purpose of 'tmp_dir' is to enable way how to test this function easily
+    """
+    path_candidates = []
+    python_name = "python%d%d_compiled" % tuple(sys.version_info[:2])
+
+    if tmp_dir:
+        home_dir = tmp_dir
+    else:
+        home_dir = os.path.expanduser('~')
+    tmp_dir = tmp_dir or tempfile.gettempdir()
+
+    home_temp_dir_name = '.' + python_name
+    home_temp_dir = os.path.join(home_dir, home_temp_dir_name)
+    path_candidates.append(home_temp_dir)
+
+    temp_dir_name = repr(os.getuid()) + '_' + python_name
+    temp_dir_path = os.path.join(tmp_dir, temp_dir_name)
+    path_candidates.append(temp_dir_path)
+
+    for path in path_candidates:
+        _create_dirs(path)
+        if check_dir(path):
+            return path
+
+    # since we got here, both dirs are not useful
+    tmp_dir_path = find_valid_temp_dir(temp_dir_name, tmp_dir)
+    if not tmp_dir_path:
+        tmp_dir_path = create_temp_dir(temp_dir_name, tmp_dir=tmp_dir)
+    return tmp_dir_path
+
+
+def default_dir_win(tmp_dir=None):
+    """
+    Create or find default catalog store for Windows systems
+
+    purpose of 'tmp_dir' is to enable way how to test this function easily
+    """
+    def create_win_temp_dir(prefix, inner_dir=None, tmp_dir=None):
+        """
+        create temp dir starting with 'prefix' in 'tmp_dir' or
+        'tempfile.gettempdir'; if 'inner_dir' is specified, it should be
+        created inside
+        """
+        tmp_dir_path = find_valid_temp_dir(prefix, tmp_dir)
+        if tmp_dir_path:
+            if inner_dir:
+                tmp_dir_path = os.path.join(tmp_dir_path, inner_dir)
+                if not os.path.isdir(tmp_dir_path):
+                    os.mkdir(tmp_dir_path, 0o700)
+        else:
+            tmp_dir_path = create_temp_dir(prefix, inner_dir, tmp_dir)
+        return tmp_dir_path
+
+    python_name = "python%d%d_compiled" % tuple(sys.version_info[:2])
+    tmp_dir = tmp_dir or tempfile.gettempdir()
+
+    temp_dir_name = "%s" % whoami()
+    temp_root_dir = os.path.join(tmp_dir, temp_dir_name)
+    temp_dir_path = os.path.join(temp_root_dir, python_name)
+    _create_dirs(temp_dir_path)
+    if check_dir(temp_dir_path) and check_dir(temp_root_dir):
+        return temp_dir_path
+    else:
+        if check_dir(temp_root_dir):
+            return create_win_temp_dir(python_name, tmp_dir=temp_root_dir)
+        else:
+            return create_win_temp_dir(temp_dir_name, python_name, tmp_dir)
+
+
 def default_dir():
     """ Return a default location to store compiled files and catalogs.
 
@@ -164,45 +247,18 @@
         in the user's home, /tmp/<uid>_pythonXX_compiled is used.  If it
         doesn't exist, it is created.  The directory is marked rwx------
         to try and keep people from being able to sneak a bad module
-        in on you.
-
-    """
-
+        in on you. If the directory already exists in /tmp/ and is not
+        secure, new one is created.
+    """
     # Use a cached value for fast return if possible
-    if hasattr(default_dir,"cached_path") and \
-       os.path.exists(default_dir.cached_path) and \
-       os.access(default_dir.cached_path, os.W_OK):
+    if hasattr(default_dir, "cached_path") and \
+       check_dir(default_dir.cached_path):
         return default_dir.cached_path
 
-    python_name = "python%d%d_compiled" % tuple(sys.version_info[:2])
-    path_candidates = []
-    if sys.platform != 'win32':
-        try:
-            path_candidates.append(os.path.join(os.environ['HOME'],
-                                                '.' + python_name))
-        except KeyError:
-            pass
-
-        temp_dir = repr(os.getuid()) + '_' + python_name
-        path_candidates.append(os.path.join(tempfile.gettempdir(), temp_dir))
+    if sys.platform == 'win32':
+        path = default_dir_win()
     else:
-        path_candidates.append(os.path.join(tempfile.gettempdir(),
-                                           "%s" % whoami(), python_name))
-
-    writable = False
-    for path in path_candidates:
-        if not os.path.exists(path):
-            try:
-                os.makedirs(path, mode=0o700)
-            except OSError:
-                continue
-        if is_writable(path):
-            writable = True
-            break
-
-    if not writable:
-        print('warning: default directory is not write accessible.')
-        print('default:', path)
+        path = default_dir_posix()
 
     # Cache the default dir path so that this function returns quickly after
     # being called once (nothing in it should change after the first call)
@@ -210,15 +266,132 @@
 
     return path
 
-def intermediate_dir():
-    """ Location in temp dir for storing .cpp and .o  files during
-        builds.
-    """
-    python_name = "python%d%d_intermediate" % tuple(sys.version_info[:2])
-    path = os.path.join(tempfile.gettempdir(),"%s"%whoami(),python_name)
-    if not os.path.exists(path):
-        os.makedirs(path, mode=0o700)
-    return path
+
+def check_dir(im_dir):
+    """
+    Check if dir is safe; if it is, return True.
+    These checks make sense only on posix:
+     * directory has correct owner
+     * directory has correct permissions (0700)
+     * directory is not a symlink
+    """
+    def check_is_dir():
+        return os.path.isdir(im_dir)
+
+    def check_permissions():
+        """ If on posix, permissions should be 0700. """
+        writable = is_writable(im_dir)
+        if sys.platform != 'win32':
+            try:
+                im_dir_stat = os.stat(im_dir)
+            except OSError:
+                return False
+            writable &= stat.S_IMODE(im_dir_stat.st_mode) == 0o0700
+        return writable
+
+    def check_ownership():
+        """ Intermediate dir owner should be same as owner of process. """
+        if sys.platform != 'win32':
+            try:
+                im_dir_stat = os.stat(im_dir)
+            except OSError:
+                return False
+            proc_uid = os.getuid()
+            return proc_uid == im_dir_stat.st_uid
+        return True
+
+    def check_is_symlink():
+        """ Check if intermediate dir is symlink. """
+        try:
+            return not os.path.islink(im_dir)
+        except OSError:
+            return False
+
+    checks = [check_is_dir, check_permissions,
+              check_ownership, check_is_symlink]
+
+    for check in checks:
+        if not check():
+            return False
+
+    return True
+
+
+def create_temp_dir(prefix, inner_dir=None, tmp_dir=None):
+    """
+    Create intermediate dirs <tmp>/<prefix+random suffix>/<inner_dir>/
+
+    argument 'tmp_dir' is used in unit tests
+    """
+    if not tmp_dir:
+        tmp_dir_path = tempfile.mkdtemp(prefix=prefix)
+    else:
+        tmp_dir_path = tempfile.mkdtemp(prefix=prefix, dir=tmp_dir)
+    if inner_dir:
... (diff truncated)
```
