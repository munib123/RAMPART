# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 2042_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2042_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 1-37 of the vulnerable file.

from collections import OrderedDict
import sys
import warnings

from django.core.exceptions import SuspiciousOperation, ImproperlyConfigured
from django.core.paginator import InvalidPage
from django.core.urlresolvers import reverse
from django.db import models
from django.db.models.fields import FieldDoesNotExist
from django.utils import six
from django.utils.deprecation import RenameMethodsBase, RemovedInDjango18Warning
from django.utils.encoding import force_text
from django.utils.translation import ugettext, ugettext_lazy
from django.utils.http import urlencode

from django.contrib.admin import FieldListFilter
from django.contrib.admin.exceptions import DisallowedModelAdminLookup
from django.contrib.admin.options import IncorrectLookupParameters, IS_POPUP_VAR, TO_FIELD_VAR
from django.contrib.admin.utils import (quote, get_fields_from_path,
    lookup_needs_distinct, prepare_lookup_value)

# Changelist settings
ALL_VAR = 'all'
ORDER_VAR = 'o'
ORDER_TYPE_VAR = 'ot'
PAGE_VAR = 'p'
SEARCH_VAR = 'q'
ERROR_FLAG = 'e'

IGNORED_PARAMS = (
    ALL_VAR, ORDER_VAR, ORDER_TYPE_VAR, SEARCH_VAR, IS_POPUP_VAR, TO_FIELD_VAR)

# Text to display within change-list table cells if the value is blank.
EMPTY_CHANGELIST_VALUE = ugettext_lazy('(None)')


def _is_changelist_popup(request):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,7 +14,9 @@
 from django.utils.http import urlencode
 
 from django.contrib.admin import FieldListFilter
-from django.contrib.admin.exceptions import DisallowedModelAdminLookup
+from django.contrib.admin.exceptions import (
+    DisallowedModelAdminLookup, DisallowedModelAdminToField,
+)
 from django.contrib.admin.options import IncorrectLookupParameters, IS_POPUP_VAR, TO_FIELD_VAR
 from django.contrib.admin.utils import (quote, get_fields_from_path,
     lookup_needs_distinct, prepare_lookup_value)
@@ -89,7 +91,10 @@
             self.page_num = 0
         self.show_all = ALL_VAR in request.GET
         self.is_popup = _is_changelist_popup(request)
-        self.to_field = request.GET.get(TO_FIELD_VAR)
+        to_field = request.GET.get(TO_FIELD_VAR)
+        if to_field and not model_admin.to_field_allowed(request, to_field):
+            raise DisallowedModelAdminToField("The field %s cannot be referenced." % to_field)
+        self.to_field = to_field
         self.params = dict(request.GET.items())
         if PAGE_VAR in self.params:
             del self.params[PAGE_VAR]
```
