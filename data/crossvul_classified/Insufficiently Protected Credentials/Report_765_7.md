# CrossVul Fix Pair: Insufficiently Protected Credentials in python
**Pair ID:** 765_7
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `765_7`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```python
Lines 1-24 of the vulnerable file.

from django.db import models

try:
    from django.contrib.auth.models import AbstractUser
except ImportError:
    from django.db.models import Model as AbstractUser


class CustomUser(AbstractUser):
    extra_field = models.CharField(max_length=2)
    new_username_field = models.CharField('userid', unique=True, max_length=20)

    USERNAME_FIELD = 'new_username_field'

    def save(self, *args, **kwargs):
        self.new_username_field = self.username
        super(CustomUser, self).save(*args, **kwargs)


class PhoneNumberUser(CustomUser):
    phone_number = models.CharField(max_length=11, default="+15555555")


class NoUsernameUser(models.Model):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 from django.db import models
 
 try:
-    from django.contrib.auth.models import AbstractUser
+    from django.contrib.auth.models import AbstractUser, UserManager
 except ImportError:
     from django.db.models import Model as AbstractUser
 
```
