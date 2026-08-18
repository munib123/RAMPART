# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 3767_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3767_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 1-28 of the vulnerable file.

import os
import re

from django.conf import global_settings, settings
from django.contrib.sites.models import Site, RequestSite
from django.contrib.auth.models import User
from django.core import mail
from django.core.urlresolvers import reverse, NoReverseMatch
from django.http import QueryDict
from django.utils.encoding import force_text
from django.utils.html import escape
from django.utils.http import urlquote
from django.test import TestCase
from django.test.utils import override_settings

from django.contrib.auth import SESSION_KEY, REDIRECT_FIELD_NAME
from django.contrib.auth.forms import (AuthenticationForm, PasswordChangeForm,
                SetPasswordForm, PasswordResetForm)
from django.contrib.auth.tests.utils import skipIfCustomUser


@override_settings(
    LANGUAGES=(
        ('en', 'English'),
    ),
    LANGUAGE_CODE='en',
    TEMPLATE_LOADERS=global_settings.TEMPLATE_LOADERS,
    TEMPLATE_DIRS=(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,7 @@
 from django.contrib.sites.models import Site, RequestSite
 from django.contrib.auth.models import User
 from django.core import mail
+from django.core.exceptions import SuspiciousOperation
 from django.core.urlresolvers import reverse, NoReverseMatch
 from django.http import QueryDict
 from django.utils.encoding import force_text
@@ -103,6 +104,42 @@
         self.assertEqual(len(mail.outbox), 1)
         self.assertEqual("staffmember@example.com", mail.outbox[0].from_email)
 
+    def test_admin_reset(self):
+        "If the reset view is marked as being for admin, the HTTP_HOST header is used for a domain override."
+        response = self.client.post('/admin_password_reset/',
+            {'email': 'staffmember@example.com'},
+            HTTP_HOST='adminsite.com'
+        )
+        self.assertEqual(response.status_code, 302)
+        self.assertEqual(len(mail.outbox), 1)
+        self.assertTrue("http://adminsite.com" in mail.outbox[0].body)
+        self.assertEqual(settings.DEFAULT_FROM_EMAIL, mail.outbox[0].from_email)
+
+    def test_poisoned_http_host(self):
+        "Poisoned HTTP_HOST headers can't be used for reset emails"
+        # This attack is based on the way browsers handle URLs. The colon
+        # should be used to separate the port, but if the URL contains an @,
+        # the colon is interpreted as part of a username for login purposes,
+        # making 'evil.com' the request domain. Since HTTP_HOST is used to
+        # produce a meaningful reset URL, we need to be certain that the
+        # HTTP_HOST header isn't poisoned. This is done as a check when get_host()
+        # is invoked, but we check here as a practical consequence.
+        with self.assertRaises(SuspiciousOperation):
+            self.client.post('/password_reset/',
+                {'email': 'staffmember@example.com'},
+                HTTP_HOST='www.example:dr.frankenstein@evil.tld'
+            )
+        self.assertEqual(len(mail.outbox), 0)
+
+    def test_poisoned_http_host_admin_site(self):
+        "Poisoned HTTP_HOST headers can't be used for reset emails on admin views"
+        with self.assertRaises(SuspiciousOperation):
+            self.client.post('/admin_password_reset/',
+                {'email': 'staffmember@example.com'},
+                HTTP_HOST='www.example:dr.frankenstein@evil.tld'
+            )
+        self.assertEqual(len(mail.outbox), 0)
+
     def _test_confirm_start(self):
         # Start by creating the email
         response = self.client.post('/password_reset/', {'email': 'staffmember@example.com'})
```
