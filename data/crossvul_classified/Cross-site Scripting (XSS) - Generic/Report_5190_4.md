# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 5190_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5190_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 1-40 of the vulnerable file.

# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import datetime
import os
import tempfile
import uuid

from django.contrib.auth.models import User
from django.contrib.contenttypes.fields import (
    GenericForeignKey, GenericRelation,
)
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.core.files.storage import FileSystemStorage
from django.db import models
from django.utils.encoding import python_2_unicode_compatible


class Section(models.Model):
    """
    A simple section that links to articles, to test linking to related items
    in admin views.
    """
    name = models.CharField(max_length=100)

    @property
    def name_property(self):
        """
        A property that simply returns the name. Used to test #24461
        """
        return self.name


@python_2_unicode_compatible
class Article(models.Model):
    """
    A simple article to test admin views. Test backwards compatibility.
    """
    title = models.CharField(max_length=100)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,12 +17,16 @@
 from django.utils.encoding import python_2_unicode_compatible
 
 
+@python_2_unicode_compatible
 class Section(models.Model):
     """
     A simple section that links to articles, to test linking to related items
     in admin views.
     """
     name = models.CharField(max_length=100)
+
+    def __str__(self):
+        return self.name
 
     @property
     def name_property(self):
```
