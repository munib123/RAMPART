# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 1622_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1622_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 1-25 of the vulnerable file.

from configparser import RawConfigParser
from attic.remote import cache_if_remote
import msgpack
import os
from binascii import hexlify
import shutil

from .helpers import Error, get_cache_dir, decode_dict, st_mtime_ns, unhexlify, UpgradableLock, int_to_bigint, \
    bigint_to_int
from .hashindex import ChunkIndex


class Cache(object):
    """Client Side cache
    """
    class RepositoryReplay(Error):
        """Cache is newer than repository, refusing to continue"""

    def __init__(self, repository, key, manifest, path=None, sync=True):
        self.timestamp = None
        self.txn_active = False
        self.repository = repository
        self.key = key
        self.manifest = manifest
        self.path = path or os.path.join(get_cache_dir(), hexlify(repository.id).decode('ascii'))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,9 +2,11 @@
 from attic.remote import cache_if_remote
 import msgpack
 import os
+import sys
 from binascii import hexlify
 import shutil
 
+from .key import PlaintextKey
 from .helpers import Error, get_cache_dir, decode_dict, st_mtime_ns, unhexlify, UpgradableLock, int_to_bigint, \
     bigint_to_int
 from .hashindex import ChunkIndex
@@ -16,7 +18,16 @@
     class RepositoryReplay(Error):
         """Cache is newer than repository, refusing to continue"""
 
-    def __init__(self, repository, key, manifest, path=None, sync=True):
+    class CacheInitAbortedError(Error):
+        """Cache initialization aborted"""
+
+
+    class EncryptionMethodMismatch(Error):
+        """Repository encryption method changed since last acccess, refusing to continue
+        """
+
+    def __init__(self, repository, key, manifest, path=None, sync=True, warn_if_unencrypted=True):
+        self.lock = None
         self.timestamp = None
         self.txn_active = False
         self.repository = repository
@@ -24,12 +35,21 @@
         self.manifest = manifest
         self.path = path or os.path.join(get_cache_dir(), hexlify(repository.id).decode('ascii'))
         if not os.path.exists(self.path):
+            if warn_if_unencrypted and isinstance(key, PlaintextKey):
+                if 'ATTIC_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK' not in os.environ:
+                    print("""Warning: Attempting to access a previously unknown unencrypted repository\n""", file=sys.stderr)
+                    answer = input('Do you want to continue? [yN] ')
+                    if not (answer and answer in 'Yy'):
+                        raise self.CacheInitAbortedError()
             self.create()
         self.open()
         if sync and self.manifest.id != self.manifest_id:
             # If repository is older than the cache something fishy is going on
             if self.timestamp and self.timestamp > manifest.timestamp:
                 raise self.RepositoryReplay()
+            # Make sure an encrypted repository has not been swapped for an unencrypted repository
+            if self.key_type is not None and self.key_type != str(key.TYPE):
+                raise self.EncryptionMethodMismatch()
             self.sync()
             self.commit()
 
@@ -65,11 +85,13 @@
         self.id = self.config.get('cache', 'repository')
         self.manifest_id = unhexlify(self.config.get('cache', 'manifest'))
         self.timestamp = self.config.get('cache', 'timestamp', fallback=None)
+        self.key_type = self.config.get('cache', 'key_type', fallback=None)
         self.chunks = ChunkIndex.read(os.path.join(self.path, 'chunks').encode('utf-8'))
         self.files = None
 
     def close(self):
-        self.lock.release()
+        if self.lock:
+            self.lock.release()
 
     def _read_files(self):
         self.files = {}
@@ -111,6 +133,7 @@
                         msgpack.pack((path_hash, item), fd)
         self.config.set('cache', 'manifest', hexlify(self.manifest.id).decode('ascii'))
         self.config.set('cache', 'timestamp', self.manifest.timestamp)
+        self.config.set('cache', 'key_type', str(self.key.TYPE))
         with open(os.path.join(self.path, 'config'), 'w') as fd:
             self.config.write(fd)
         self.chunks.write(os.path.join(self.path, 'chunks').encode('utf-8'))
```
