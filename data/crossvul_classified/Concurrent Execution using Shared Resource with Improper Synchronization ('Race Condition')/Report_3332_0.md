# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in python
**Pair ID:** 3332_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3332_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```python
Lines 40-80 of the vulnerable file.


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
import functools
import hashlib
import os
from importlib import import_module


def load(configuration, logger):
    """Load the authentication manager chosen in configuration."""
    auth_type = configuration.get("auth", "type")
    logger.debug("Authentication type is %s", auth_type)
    if auth_type == "None":
        class_ = NoneAuth
    elif auth_type == "htpasswd":
        class_ = Auth
    else:
        class_ = import_module(auth_type).Auth
    return class_(configuration, logger)


class BaseAuth:
    def __init__(self, configuration, logger):
        self.configuration = configuration
        self.logger = logger

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,6 +57,8 @@
 import functools
 import hashlib
 import os
+import random
+import time
 from importlib import import_module
 
 
@@ -192,6 +194,8 @@
                 line = line.strip()
                 if line:
                     login, hash_value = line.split(":")
-                    if login == user:
-                        return self.verify(hash_value, password)
+                    if login == user and self.verify(hash_value, password):
+                        return True
+        # Random timer to avoid timing oracles and simple bruteforce attacks
+        time.sleep(1 + random.random())
         return False
```
