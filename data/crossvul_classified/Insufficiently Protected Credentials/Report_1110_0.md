# CrossVul Fix Pair: Insufficiently Protected Credentials in python
**Pair ID:** 1110_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1110_0`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```python
Lines 1-33 of the vulnerable file.

from functools import partial

import django_otp
from django.conf import settings
from django.contrib.auth.views import redirect_to_login
from django.urls import NoReverseMatch, reverse
from django.utils.functional import SimpleLazyObject
from django_otp.middleware import OTPMiddleware as _OTPMiddleware


class VerifyUserMiddleware(_OTPMiddleware):
    _allowed_url_names = [
        "wagtail_2fa_auth",
        "wagtail_2fa_device_list",
        "wagtail_2fa_device_new",
        "wagtail_2fa_device_qrcode",
        "wagtailadmin_login",
        "wagtailadmin_logout",
    ]

    def __call__(self, request):
        if hasattr(self, 'process_request'):
            response = self.process_request(request)
        if not response:
            response = self.get_response(request)
        if hasattr(self, 'process_response'):
            response = self.process_response(request, response)
        return response

    def process_request(self, request):
        if request.user:
            request.user = SimpleLazyObject(partial(self._verify_user, request, request.user))
        user = request.user
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,6 +10,11 @@
 
 class VerifyUserMiddleware(_OTPMiddleware):
     _allowed_url_names = [
+        "wagtail_2fa_auth",
+        "wagtailadmin_login",
+        "wagtailadmin_logout",
+    ]
+    _allowed_url_names_no_device = [
         "wagtail_2fa_auth",
         "wagtail_2fa_device_list",
         "wagtail_2fa_device_new",
@@ -66,24 +71,26 @@
             return False
 
         # Allow the user to a fixed number of paths when not verified
-        if request.path in self._allowed_paths:
+        user_has_device = django_otp.user_has_device(user, confirmed=True)
+        if request.path in self._get_allowed_paths(user_has_device):
             return False
 
         # For all other cases require that the user is verfied via otp
         return True
 
-    @property
-    def _allowed_paths(self):
-        """Return the paths the user may visit when not verified via otp
+    def _get_allowed_paths(self, has_device):
+        """Return the paths the user may visit when not verified via otp.
 
-        This result cannot be cached since we want to be compatible with the
-        django-hosts package. Django-hosts alters the urlconf based on the
-        hostname in the request, so the urls might exist for admin.<domain> but
-        not for www.<domain>.
+        If the user already has a registered device, return a limited set of
+        paths to prevent them from adding or listing devices to prevent them
+        from adding or listing devices.
+        """
+        allowed_url_names = self._allowed_url_names
+        if not has_device:
+            allowed_url_names = self._allowed_url_names_no_device
 
-        """
         results = []
-        for route_name in self._allowed_url_names:
+        for route_name in allowed_url_names:
             try:
                 results.append(settings.WAGTAIL_MOUNT_PATH + reverse(route_name))
             except NoReverseMatch:
```
