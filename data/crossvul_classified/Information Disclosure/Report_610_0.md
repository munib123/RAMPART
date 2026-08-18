# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 610_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `610_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 1-25 of the vulnerable file.

import warnings

import six
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View

from ..exceptions import AnymailInsecureWebhookWarning, AnymailWebhookValidationFailure
from ..utils import get_anymail_setting, collect_all_methods, get_request_basic_auth


class AnymailBasicAuthMixin(object):
    """Implements webhook basic auth as mixin to AnymailBaseWebhookView."""

    # Whether to warn if basic auth is not configured.
    # For most ESPs, basic auth is the only webhook security,
    # so the default is True. Subclasses can set False if
    # they enforce other security (like signed webhooks).
    warn_if_no_basic_auth = True

    # List of allowable HTTP basic-auth 'user:pass' strings.
    basic_auth = None  # (Declaring class attr allows override by kwargs in View.as_view.)

    def __init__(self, **kwargs):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,6 +2,7 @@
 
 import six
 from django.http import HttpResponse
+from django.utils.crypto import constant_time_compare
 from django.utils.decorators import method_decorator
 from django.views.decorators.csrf import csrf_exempt
 from django.views.generic import View
@@ -40,8 +41,13 @@
     def validate_request(self, request):
         """If configured for webhook basic auth, validate request has correct auth."""
         if self.basic_auth:
-            basic_auth = get_request_basic_auth(request)
-            if basic_auth is None or basic_auth not in self.basic_auth:
+            request_auth = get_request_basic_auth(request)
+            # Use constant_time_compare to avoid timing attack on basic auth. (It's OK that any()
+            # can terminate early: we're not trying to protect how many auth strings are allowed,
+            # just the contents of each individual auth string.)
+            auth_ok = any(constant_time_compare(request_auth, allowed_auth)
+                          for allowed_auth in self.basic_auth)
+            if not auth_ok:
                 # noinspection PyUnresolvedReferences
                 raise AnymailWebhookValidationFailure(
                     "Missing or invalid basic auth in Anymail %s webhook" % self.esp_name)
@@ -77,8 +83,11 @@
         *All* definitions of this method in the class chain (including mixins)
         will be called. There is no need to chain to the superclass.
         (See self.run_validators and collect_all_methods.)
+
+        Security note: use django.utils.crypto.constant_time_compare for string
+        comparisons, to avoid exposing your validation to a timing attack.
         """
-        # if request.POST['signature'] != expected_signature:
+        # if not constant_time_compare(request.POST['signature'], expected_signature):
         #     raise AnymailWebhookValidationFailure("...message...")
         # (else just do nothing)
         pass
```
