# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 4954_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4954_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 1-27 of the vulnerable file.

from __future__ import unicode_literals

import base64
import binascii
import hashlib
import importlib
from collections import OrderedDict

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed
from django.dispatch import receiver
from django.utils import lru_cache
from django.utils.crypto import (
    constant_time_compare, get_random_string, pbkdf2,
)
from django.utils.encoding import force_bytes, force_str, force_text
from django.utils.module_loading import import_string
from django.utils.translation import ugettext_noop as _

UNUSABLE_PASSWORD_PREFIX = '!'  # This will never be a valid encoded hash
UNUSABLE_PASSWORD_SUFFIX_LENGTH = 40  # number of random chars to add after UNUSABLE_PASSWORD_PREFIX


def is_password_usable(encoded):
    if encoded is None or encoded.startswith(UNUSABLE_PASSWORD_PREFIX):
        return False
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,6 +4,7 @@
 import binascii
 import hashlib
 import importlib
+import warnings
 from collections import OrderedDict
 
 from django.conf import settings
@@ -46,10 +47,17 @@
     preferred = get_hasher(preferred)
     hasher = identify_hasher(encoded)
 
-    must_update = hasher.algorithm != preferred.algorithm
-    if not must_update:
-        must_update = preferred.must_update(encoded)
+    hasher_changed = hasher.algorithm != preferred.algorithm
+    must_update = hasher_changed or preferred.must_update(encoded)
     is_correct = hasher.verify(password, encoded)
+
+    # If the hasher didn't change (we don't protect against enumeration if it
+    # does) and the password should get updated, try to close the timing gap
+    # between the work factor of the current encoded password and the default
+    # work factor.
+    if not is_correct and not hasher_changed and must_update:
+        hasher.harden_runtime(password, encoded)
+
     if setter and is_correct and must_update:
         setter(password)
     return is_correct
@@ -216,6 +224,19 @@
     def must_update(self, encoded):
         return False
 
+    def harden_runtime(self, password, encoded):
+        """
+        Bridge the runtime gap between the work factor supplied in `encoded`
+        and the work factor suggested by this hasher.
+
+        Taking PBKDF2 as an example, if `encoded` contains 20000 iterations and
+        `self.iterations` is 30000, this method should run password through
+        another 10000 iterations of PBKDF2. Similar approaches should exist
+        for any hasher that has a work factor. If not, this method should be
+        defined as a no-op to silence the warning.
+        """
+        warnings.warn('subclasses of BasePasswordHasher should provide a harden_runtime() method')
+
 
 class PBKDF2PasswordHasher(BasePasswordHasher):
     """
@@ -257,6 +278,12 @@
     def must_update(self, encoded):
         algorithm, iterations, salt, hash = encoded.split('$', 3)
         return int(iterations) != self.iterations
+
+    def harden_runtime(self, password, encoded):
+        algorithm, iterations, salt, hash = encoded.split('$', 3)
+        extra_iterations = self.iterations - int(iterations)
+        if extra_iterations > 0:
+            self.encode(password, salt, extra_iterations)
 
 
 class PBKDF2SHA1PasswordHasher(PBKDF2PasswordHasher):
@@ -305,23 +332,8 @@
     def verify(self, password, encoded):
         algorithm, data = encoded.split('$', 1)
         assert algorithm == self.algorithm
-        bcrypt = self._load_library()
-
-        # Hash the password prior to using bcrypt to prevent password
-        # truncation as described in #20138.
-        if self.digest is not None:
-            # Use binascii.hexlify() because a hex encoded bytestring is
-            # Unicode on Python 3.
-            password = binascii.hexlify(self.digest(force_bytes(password)).digest())
-        else:
-            password = force_bytes(password)
-
-        # Ensure that our data is a bytestring
-        data = force_bytes(data)
-        # force_bytes() necessary for py-bcrypt compatibility
-        hashpw = force_bytes(bcrypt.hashpw(password, data))
-
-        return constant_time_compare(data, hashpw)
+        encoded_2 = self.encode(password, force_bytes(data))
+        return constant_time_compare(encoded, encoded_2)
 
     def safe_summary(self, encoded):
         algorithm, empty, algostr, work_factor, data = encoded.split('$', 4)
@@ -338,6 +350,16 @@
         algorithm, empty, algostr, rounds, data = encoded.split('$', 4)
         return int(rounds) != self.rounds
 
+    def harden_runtime(self, password, encoded):
+        _, data = encoded.split('$', 1)
+        salt = data[:29]  # Length of the salt in bcrypt.
+        rounds = data.split('$')[2]
+        # work factor is logarithmic, adding one doubles the load.
+        diff = 2**(self.rounds - int(rounds)) - 1
+        while diff > 0:
+            self.encode(password, force_bytes(salt))
+            diff -= 1
+
 
 class BCryptPasswordHasher(BCryptSHA256PasswordHasher):
     """
@@ -385,6 +407,9 @@
             (_('hash'), mask_hash(hash)),
         ])
 
+    def harden_runtime(self, password, encoded):
+        pass
+
 
 class MD5PasswordHasher(BasePasswordHasher):
     """
@@ -413,6 +438,9 @@
             (_('hash'), mask_hash(hash)),
         ])
 
+    def harden_runtime(self, password, encoded):
+        pass
+
 
 class UnsaltedSHA1PasswordHasher(BasePasswordHasher):
     """
@@ -444,6 +472,9 @@
             (_('algorithm'), self.algorithm),
             (_('hash'), mask_hash(hash)),
         ])
+
+    def harden_runtime(self, password, encoded):
+        pass
 
 
 class UnsaltedMD5PasswordHasher(BasePasswordHasher):
@@ -477,6 +508,9 @@
             (_('algorithm'), self.algorithm),
             (_('hash'), mask_hash(encoded, show=3)),
         ])
+
+    def harden_runtime(self, password, encoded):
+        pass
 
 
 class CryptPasswordHasher(BasePasswordHasher):
@@ -512,3 +546,6 @@
             (_('salt'), salt),
             (_('hash'), mask_hash(data, show=3)),
         ])
+
+    def harden_runtime(self, password, encoded):
+        pass
```
