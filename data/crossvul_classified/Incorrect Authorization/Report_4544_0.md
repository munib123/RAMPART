# CrossVul Fix Pair: Incorrect Authorization in python
**Pair ID:** 4544_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4544_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```python
Lines 1-21 of the vulnerable file.

import qrcode
import qrcode.image.svg
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.views import SuccessURLAllowedHostsMixin
from django.http import HttpResponse
from django.shortcuts import resolve_url
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.functional import cached_property
from django.utils.http import is_safe_url
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import (
    DeleteView, FormView, ListView, UpdateView, View)
from django_otp import login as otp_login
from django_otp.plugins.otp_totp.models import TOTPDevice

from wagtail_2fa import forms, utils
from wagtail_2fa.mixins import OtpRequiredMixin

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,4 @@
+from django.core.exceptions import PermissionDenied
 import qrcode
 import qrcode.image.svg
 from django.conf import settings
@@ -75,6 +76,15 @@
         context['user_id'] = int(self.kwargs['user_id'])
         return context
 
+    def dispatch(self, request, *args, **kwargs):
+        if (int(self.kwargs["user_id"]) == request.user.pk or
+                request.user.has_perm("user.change_user")):
+            if not self.user_allowed(request.user):
+                return self.handle_no_permission(request)
+
+            return super(OtpRequiredMixin, self).dispatch(request, *args, **kwargs)
+        raise PermissionDenied
+
 
 class DeviceCreateView(OtpRequiredMixin, FormView):
     form_class = forms.DeviceForm
@@ -134,6 +144,17 @@
     def get_success_url(self):
         return reverse('wagtail_2fa_device_list', kwargs={'user_id': self.request.POST.get('user_id')})
 
+    def dispatch(self, request, *args, **kwargs):
+        device = TOTPDevice.objects.get(**self.kwargs)
+
+        if device.user.pk == request.user.pk or request.user.has_perm("user.change_user"):
+            if not self.user_allowed(request.user):
+                return self.handle_no_permission(request)
+
+            return super(OtpRequiredMixin, self).dispatch(request, *args, **kwargs)
+
+        raise PermissionDenied
+
 
 class DeviceQRCodeView(OtpRequiredMixin, View):
     # require OTP if configured
```
