# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in python
**Pair ID:** 3333_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3333_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```python
Lines 39-79 of the vulnerable file.


The following htpasswd password encrpytion methods are supported by Radicale
out-of-the-box:

    - plain-text (created by htpasswd -p...) -- INSECURE
    - CRYPT      (created by htpasswd -d...) -- INSECURE
    - SHA1       (created by htpasswd -s...) -- INSECURE

When passlib (https://pypi.python.org/pypi/passlib) is importable, the
following significantly more secure schemes are parsable by Radicale:

    - MD5-APR1   (htpasswd -m...) -- htpasswd's default method
    - BCRYPT     (htpasswd -B...) -- Requires htpasswd 2.4.x

"""


import base64
import hashlib
import os


from .. import config


FILENAME = os.path.expanduser(config.get("auth", "htpasswd_filename"))
ENCRYPTION = config.get("auth", "htpasswd_encryption")


def _plain(hash_value, password):
    """Check if ``hash_value`` and ``password`` match, using plain method."""
    return hash_value == password


def _crypt(hash_value, password):
    """Check if ``hash_value`` and ``password`` match, using crypt method."""
    return crypt.crypt(password, hash_value) == hash_value


def _sha1(hash_value, password):
    """Check if ``hash_value`` and ``password`` match, using sha1 method."""
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,7 +56,8 @@
 import base64
 import hashlib
 import os
-
+import random
+import time
 
 from .. import config
 
@@ -161,7 +162,10 @@
             if strippedline:
                 login, hash_value = strippedline.split(":")
                 if login == user:
-                    # Allow encryption method to be overridden at runtime.
-                    return _verifuncs[ENCRYPTION](hash_value, password)
+                    if _verifuncs[ENCRYPTION](hash_value, password):
+                        # Allow encryption method to be overridden at runtime.
+                        return True
+    # Random timer to avoid timing oracles and simple bruteforce attacks
+    time.sleep(1 + random.random())
     return False
 
```
