# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 2042_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2042_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 1-34 of the vulnerable file.

from collections import OrderedDict
import copy
import operator
from functools import partial, reduce, update_wrapper
import warnings

from django import forms
from django.conf import settings
from django.contrib import messages
from django.contrib.admin import widgets, helpers
from django.contrib.admin import validation
from django.contrib.admin.checks import (BaseModelAdminChecks, ModelAdminChecks,
    InlineModelAdminChecks)
from django.contrib.admin.utils import (quote, unquote, flatten_fieldsets,
    get_deleted_objects, model_format_dict, NestedObjects,
    lookup_needs_distinct)
from django.contrib.admin.templatetags.admin_static import static
from django.contrib.admin.templatetags.admin_urls import add_preserved_filters
from django.contrib.auth import get_permission_codename
from django.core import checks
from django.core.exceptions import (PermissionDenied, ValidationError,
    FieldError, ImproperlyConfigured)
from django.core.paginator import Paginator
from django.core.urlresolvers import reverse
from django.db import models, transaction, router
from django.db.models.constants import LOOKUP_SEP
from django.db.models.related import RelatedObject
from django.db.models.fields import BLANK_CHOICE_DASH, FieldDoesNotExist
from django.db.models.sql.constants import QUERY_TERMS
from django.forms.formsets import all_valid, DELETION_FIELD_NAME
from django.forms.models import (modelform_factory, modelformset_factory,
    inlineformset_factory, BaseInlineFormSet, modelform_defines_fields)
from django.http import Http404, HttpResponseRedirect
from django.http.response import HttpResponseBase
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,6 +11,7 @@
 from django.contrib.admin import validation
 from django.contrib.admin.checks import (BaseModelAdminChecks, ModelAdminChecks,
     InlineModelAdminChecks)
+from django.contrib.admin.exceptions import DisallowedModelAdminToField
 from django.contrib.admin.utils import (quote, unquote, flatten_fieldsets,
     get_deleted_objects, model_format_dict, NestedObjects,
     lookup_needs_distinct)
@@ -434,6 +435,24 @@
                 valid_lookups.append(filter_item)
         return clean_lookup in valid_lookups
 
+    def to_field_allowed(self, request, to_field):
+        opts = self.model._meta
+
+        try:
+            field = opts.get_field(to_field)
+        except FieldDoesNotExist:
+            return False
+
+        # Make sure at least one of the models registered for this site
+        # references this field.
+        registered_models = self.admin_site._registry
+        for related_object in opts.get_all_related_objects():
+            if (related_object.model in registered_models and
+                    field in related_object.field.foreign_related_fields):
+                return True
+
+        return False
+
     def has_add_permission(self, request):
         """
         Returns True if the given request has permission to add an object.
@@ -1325,6 +1344,10 @@
     @transaction.atomic
     def changeform_view(self, request, object_id=None, form_url='', extra_context=None):
 
+        to_field = request.POST.get(TO_FIELD_VAR, request.GET.get(TO_FIELD_VAR))
+        if to_field and not self.to_field_allowed(request, to_field):
+            raise DisallowedModelAdminToField("The field %s cannot be referenced." % to_field)
+
         model = self.model
         opts = model._meta
         add = object_id is None
@@ -1397,8 +1420,7 @@
             original=obj,
             is_popup=(IS_POPUP_VAR in request.POST or
                       IS_POPUP_VAR in request.GET),
-            to_field=request.POST.get(TO_FIELD_VAR,
-                                      request.GET.get(TO_FIELD_VAR)),
+            to_field=to_field,
             media=media,
             inline_admin_formsets=inline_formsets,
             errors=helpers.AdminErrorList(form, formsets),
```
