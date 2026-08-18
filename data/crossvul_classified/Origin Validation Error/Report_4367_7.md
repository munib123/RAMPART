# CrossVul Fix Pair: Origin Validation Error in python
**Pair ID:** 4367_7
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4367_7`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```python
Lines 1-15 of the vulnerable file.

# SPDX-License-Identifier: EUPL-1.2
# Copyright (C) 2019 - 2020 Dimpact
import factory


class UserFactory(factory.django.DjangoModelFactory):
    username = factory.Sequence(lambda n: f"user-{n}")

    class Meta:
        model = "accounts.User"


class SuperUserFactory(UserFactory):
    is_staff = True
    is_superuser = True
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,7 @@
 
 class UserFactory(factory.django.DjangoModelFactory):
     username = factory.Sequence(lambda n: f"user-{n}")
+    password = factory.PostGenerationMethodCall("set_password")
 
     class Meta:
         model = "accounts.User"
```
