# CrossVul Fix Pair: Cleartext Storage of Sensitive Information in python
**Pair ID:** 4092_3
**Vulnerability Class:** Cleartext Storage of Sensitive Information
**CWE:** CWE-312
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4092_3`)

## Vulnerability Information & PoC

## Description
Cleartext Storage of Sensitive Information - Because the information is stored in cleartext (i.

## Vulnerable Code
```python
Lines 1-25 of the vulnerable file.

import logging
import warnings
from base64 import b32encode
from binascii import unhexlify

import django_otp
import qrcode
import qrcode.image.svg
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.views import SuccessURLAllowedHostsMixin
from django.contrib.sites.shortcuts import get_current_site
from django.forms import Form
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect, resolve_url
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.http import is_safe_url
from django.utils.module_loading import import_string
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import DeleteView, FormView, TemplateView
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,6 +2,7 @@
 import warnings
 from base64 import b32encode
 from binascii import unhexlify
+import time
 
 import django_otp
 import qrcode
@@ -12,13 +13,15 @@
 from django.contrib.auth.forms import AuthenticationForm
 from django.contrib.auth.views import SuccessURLAllowedHostsMixin
 from django.contrib.sites.shortcuts import get_current_site
-from django.forms import Form
+from django.forms import Form, ValidationError
 from django.http import Http404, HttpResponse, HttpResponseRedirect
 from django.shortcuts import redirect, resolve_url
 from django.urls import reverse
 from django.utils.decorators import method_decorator
+from django.utils.functional import cached_property
 from django.utils.http import is_safe_url
 from django.utils.module_loading import import_string
+from django.utils.translation import gettext as _
 from django.views.decorators.cache import never_cache
 from django.views.decorators.csrf import csrf_protect
 from django.views.decorators.debug import sensitive_post_parameters
@@ -72,6 +75,7 @@
         'backup': False,
     }
     redirect_authenticated_user = False
+    storage_name = 'two_factor.views.utils.LoginStorage'
 
     def has_token_step(self):
         return default_device(self.get_user())
@@ -79,6 +83,14 @@
     def has_backup_step(self):
         return default_device(self.get_user()) and \
             'token' not in self.storage.validated_step_data
+
+    @cached_property
+    def expired(self):
+        login_timeout = getattr(settings, 'TWO_FACTOR_LOGIN_TIMEOUT', 600)
+        if login_timeout == 0:
+            return False
+        expiration_time = self.storage.data.get("authentication_time", 0) + login_timeout
+        return int(time.time()) > expiration_time
 
     condition_dict = {
         'token': has_token_step,
@@ -90,12 +102,25 @@
         super().__init__(**kwargs)
         self.user_cache = None
         self.device_cache = None
+        self.show_timeout_error = False
 
     def post(self, *args, **kwargs):
         """
         The user can select a particular device to challenge, being the backup
         devices added to the account.
         """
+        wizard_goto_step = self.request.POST.get('wizard_goto_step', None)
+
+        if wizard_goto_step == 'auth':
+            self.storage.reset()
+
+        if self.expired and self.steps.current != 'auth':
+            logger.info("User's authentication flow has timed out. The user "
+                        "has been redirected to the initial auth form.")
+            self.storage.reset()
+            self.show_timeout_error = True
+            return self.render_goto_step('auth')
+
         # Generating a challenge doesn't require to validate the form.
         if 'challenge_device' in self.request.POST:
             return self.render_goto_step('token')
@@ -151,6 +176,54 @@
                 'initial_device': self.get_device(step),
             }
         return {}
+
+    def get_done_form_list(self):
+        """
+        Return the forms that should be processed during the final step
+        """
+        # Intentionally do not process the auth form on the final step. We
+        # haven't stored this data, and it isn't required to login the user
+        form_list = self.get_form_list()
+        form_list.pop('auth')
+        return form_list
+
+    def process_step(self, form):
+        """
+        Process an individual step in the flow
+        """
+        # To prevent saving any private auth data to the session store, we
+        # validate the authentication form, determine the resulting user, then
+        # only store the minimum needed to login that user (the user's primary
+        # key and the backend used)
+        if self.steps.current == 'auth':
+            user = form.is_valid() and form.user_cache
+            self.storage.reset()
+            self.storage.authenticated_user = user
+            self.storage.data["authentication_time"] = int(time.time())
+
+            # By returning None when the user clicks the "back" button to the
+            # auth step the form will be blank with validation warnings
+            return None
+
+        return super().process_step(form)
+
+    def process_step_files(self, form):
+        """
+        Process the files submitted from a specific test
+        """
+        if self.steps.current == 'auth':
+            return {}
+        return super().process_step_files(form)
+
+    def get_form(self, *args, **kwargs):
+        """
+        Returns the form for the step
+        """
+        form = super().get_form(*args, **kwargs)
+        if self.show_timeout_error:
+            form.cleaned_data = getattr(form, 'cleaned_data', {})
+            form.add_error(None, ValidationError(_('Your session has timed out. Please login again.')))
+        return form
 
     def get_device(self, step=None):
         """
@@ -187,9 +260,7 @@
         if not a valid user; see also issue #65.
         """
         if not self.user_cache:
-            form_obj = self.get_form(step='auth',
-                                     data=self.storage.get_step_data('auth'))
-            self.user_cache = form_obj.is_valid() and form_obj.user_cache
+            self.user_cache = self.storage.authenticated_user
         return self.user_cache
 
     def get_context_data(self, form, **kwargs):
```
