# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 1622_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1622_3`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 1-21 of the vulnerable file.

import os
from io import StringIO
import stat
import subprocess
import sys
import shutil
import tempfile
import time
import unittest
from hashlib import sha256
from attic import xattr
from attic.archive import Archive, ChunkBuffer
from attic.archiver import Archiver
from attic.crypto import bytes_to_long, num_aes_blocks
from attic.helpers import Manifest
from attic.remote import RemoteRepository, PathNotAllowed
from attic.repository import Repository
from attic.testsuite import AtticTestCase
from attic.testsuite.mock import patch

try:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,5 @@
+from binascii import hexlify
+from configparser import RawConfigParser
 import os
 from io import StringIO
 import stat
@@ -11,6 +13,7 @@
 from attic import xattr
 from attic.archive import Archive, ChunkBuffer
 from attic.archiver import Archiver
+from attic.cache import Cache
 from attic.crypto import bytes_to_long, num_aes_blocks
 from attic.helpers import Manifest
 from attic.remote import RemoteRepository, PathNotAllowed
@@ -39,6 +42,22 @@
 
     def __exit__(self, *args, **kw):
         os.chdir(self.old)
+
+
+class environment_variable:
+    def __init__(self, **values):
+        self.values = values
+        self.old_values = {}
+
+    def __enter__(self):
+        for k, v in self.values.items():
+            self.old_values[k] = os.environ.get(k)
+            os.environ[k] = v
+
+    def __exit__(self, *args, **kw):
+        for k, v in self.old_values.items():
+            if v is not None:
+                os.environ[k] = v
 
 
 class ArchiverTestCaseBase(AtticTestCase):
@@ -161,10 +180,34 @@
         info_output = self.attic('info', self.repository_location + '::test')
         self.assert_in('Number of files: 4', info_output)
         shutil.rmtree(self.cache_path)
-        info_output2 = self.attic('info', self.repository_location + '::test')
+        with environment_variable(ATTIC_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK='1'):
+            info_output2 = self.attic('info', self.repository_location + '::test')
         # info_output2 starts with some "initializing cache" text but should
         # end the same way as info_output
         assert info_output2.endswith(info_output)
+
+    def _extract_repository_id(self, path):
+        return Repository(self.repository_path).id
+
+    def _set_repository_id(self, path, id):
+        config = RawConfigParser()
+        config.read(os.path.join(path, 'config'))
+        config.set('repository', 'id', hexlify(id).decode('ascii'))
+        with open(os.path.join(path, 'config'), 'w') as fd:
+            config.write(fd)
+        return Repository(self.repository_path).id
+
+    def test_repository_swap_detection(self):
+        self.create_test_files()
+        os.environ['ATTIC_PASSPHRASE'] = 'passphrase'
+        self.attic('init', '--encryption=passphrase', self.repository_location)
+        repository_id = self._extract_repository_id(self.repository_path)
+        self.attic('create', self.repository_location + '::test', 'input')
+        shutil.rmtree(self.repository_path)
+        self.attic('init', '--encryption=none', self.repository_location)
+        self._set_repository_id(self.repository_path, repository_id)
+        self.assert_equal(repository_id, self._extract_repository_id(self.repository_path))
+        self.assert_raises(Cache.EncryptionMethodMismatch, lambda :self.attic('create', self.repository_location + '::test.2', 'input'))
 
     def test_strip_components(self):
         self.attic('init', self.repository_location)
```
