# CrossVul Fix Pair: Cleartext Storage of Sensitive Information in python
**Pair ID:** 4092_4
**Vulnerability Class:** Cleartext Storage of Sensitive Information
**CWE:** CWE-312
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4092_4`)

## Vulnerability Information & PoC

## Description
Cleartext Storage of Sensitive Information - Because the information is stored in cleartext (i.

## Vulnerable Code
```python
Lines 1-23 of the vulnerable file.

import logging

from django.core.exceptions import SuspiciousOperation
from django.utils.decorators import method_decorator
from django.utils.translation import gettext as _
from formtools.wizard.forms import ManagementForm
from formtools.wizard.storage.session import SessionStorage
from formtools.wizard.views import SessionWizardView

logger = logging.getLogger(__name__)


class ExtraSessionStorage(SessionStorage):
    """
    SessionStorage that includes the property `validated_step_data` for storing
    cleaned form data per step.
    """
    validated_step_data_key = 'validated_step_data'

    def init_data(self):
        super().init_data()
        self.data[self.validated_step_data_key] = {}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,6 @@
 import logging
 
+from django.contrib.auth import load_backend
 from django.core.exceptions import SuspiciousOperation
 from django.utils.decorators import method_decorator
 from django.utils.translation import gettext as _
@@ -35,6 +36,33 @@
 
     validated_step_data = property(_get_validated_step_data,
                                    _set_validated_step_data)
+
+
+class LoginStorage(ExtraSessionStorage):
+    """
+    SessionStorage that includes the property 'authenticated_user' for storing
+    backend authenticated users while logging in.
+    """
+    def _get_authenticated_user(self):
+        # Ensure that both user_pk and user_backend exist in the session
+        if not all([self.data.get("user_pk"), self.data.get("user_backend")]):
+            return False
+        # Acquire the user the same way django.contrib.auth.get_user does
+        backend = load_backend(self.data["user_backend"])
+        user = backend.get_user(self.data["user_pk"])
+        if not user:
+            return False
+        # Set user.backend to the dotted path version of the backend for login()
+        user.backend = self.data["user_backend"]
+        return user
+
+    def _set_authenticated_user(self, user):
+        # Acquire the PK the same way django's auth middleware does
+        self.data["user_pk"] = user._meta.pk.value_to_string(user)
+        self.data["user_backend"] = user.backend
+
+    authenticated_user = property(_get_authenticated_user,
+                                  _set_authenticated_user)
 
 
 class IdempotentSessionWizardView(SessionWizardView):
@@ -153,6 +181,9 @@
 
         return super().process_step(form)
 
+    def get_done_form_list(self):
+        return self.get_form_list()
+
     def render_done(self, form, **kwargs):
         """
         This method gets called when all forms passed. The method should also
@@ -162,7 +193,7 @@
         """
         final_form_list = []
         # walk through the form list and try to validate the data again.
-        for form_key in self.get_form_list():
+        for form_key in self.get_done_form_list():
             form_obj = self.get_form(step=form_key,
                                      data=self.storage.get_step_data(form_key),
                                      files=self.storage.get_step_files(
```
