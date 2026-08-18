# CrossVul Fix Pair: Insufficiently Protected Credentials in python
**Pair ID:** 765_5
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `765_5`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```python
Lines 1-23 of the vulnerable file.

# -*- coding: utf-8 -*-
import hashlib
import os

from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _


class LoginCode(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='login_codes',
                             editable=False, verbose_name=_('user'), on_delete=models.CASCADE)
    code = models.CharField(max_length=20, editable=False, verbose_name=_('code'))
    timestamp = models.DateTimeField(editable=False)
    next = models.TextField(editable=False, blank=True)

    def __str__(self):
        return "%s - %s" % (self.user, self.timestamp)

    def save(self, *args, **kwargs):
        self.timestamp = timezone.now()

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 # -*- coding: utf-8 -*-
 import hashlib
-import os
+import uuid
 
 from django.conf import settings
 from django.db import models
@@ -9,14 +9,26 @@
 
 
 class LoginCode(models.Model):
+    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
     user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='login_codes',
                              editable=False, verbose_name=_('user'), on_delete=models.CASCADE)
-    code = models.CharField(max_length=20, editable=False, verbose_name=_('code'))
     timestamp = models.DateTimeField(editable=False)
     next = models.TextField(editable=False, blank=True)
 
     def __str__(self):
         return "%s - %s" % (self.user, self.timestamp)
+
+    @property
+    def code(self):
+        hash_algorithm = getattr(settings, 'NOPASSWORD_HASH_ALGORITHM', 'sha256')
+        m = getattr(hashlib, hash_algorithm)()
+        m.update(getattr(settings, 'SECRET_KEY', None).encode('utf-8'))
+        m.update(str(self.id).encode())
+        if getattr(settings, 'NOPASSWORD_NUMERIC_CODES', False):
+            hashed = str(int(m.hexdigest(), 16))
+        else:
+            hashed = m.hexdigest()
+        return hashed
 
     def save(self, *args, **kwargs):
         self.timestamp = timezone.now()
@@ -31,21 +43,8 @@
         if not user.is_active:
             return None
 
-        code = cls.generate_code()
-        login_code = LoginCode(user=user, code=code)
+        login_code = LoginCode(user=user)
         if next is not None:
             login_code.next = next
         login_code.save()
         return login_code
-
-    @classmethod
-    def generate_code(cls):
-        hash_algorithm = getattr(settings, 'NOPASSWORD_HASH_ALGORITHM', 'sha256')
-        m = getattr(hashlib, hash_algorithm)()
-        m.update(getattr(settings, 'SECRET_KEY', None).encode('utf-8'))
-        m.update(os.urandom(16))
-        if getattr(settings, 'NOPASSWORD_NUMERIC_CODES', False):
-            hashed = str(int(m.hexdigest(), 16))
-        else:
-            hashed = m.hexdigest()
-        return hashed
```
