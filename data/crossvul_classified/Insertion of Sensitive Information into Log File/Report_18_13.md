# CrossVul Fix Pair: Insertion of Sensitive Information into Log File in python
**Pair ID:** 18_13
**Vulnerability Class:** Insertion of Sensitive Information into Log File
**CWE:** CWE-532
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `18_13`)

## Vulnerability Information & PoC

## Description
Insertion of Sensitive Information into Log File - While logging all information may be helpful during development stages, it is important that logging levels be set appropriately before a product ships so that sensitive user data and system inform...

## Vulnerable Code
```python
Lines 1-37 of the vulnerable file.

import base64

from django.test import override_settings, SimpleTestCase
from mock import create_autospec, ANY

from anymail.exceptions import AnymailInsecureWebhookWarning
from anymail.signals import tracking, inbound

from .utils import AnymailTestMixin, ClientWithCsrfChecks


def event_handler(sender, event, esp_name, **kwargs):
    """Prototypical webhook signal handler"""
    pass


@override_settings(ANYMAIL={'WEBHOOK_AUTHORIZATION': 'username:password'})
class WebhookTestCase(AnymailTestMixin, SimpleTestCase):
    """Base for testing webhooks

    - connects webhook signal handlers
    - sets up basic auth by default (since most ESP webhooks warn if it's not enabled)
    """

    client_class = ClientWithCsrfChecks

    def setUp(self):
        super(WebhookTestCase, self).setUp()
        # Use correct basic auth by default (individual tests can override):
        self.set_basic_auth()

        # Install mocked signal handlers
        self.tracking_handler = create_autospec(event_handler)
        tracking.connect(self.tracking_handler)
        self.addCleanup(tracking.disconnect, self.tracking_handler)

        self.inbound_handler = create_autospec(event_handler)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,7 +14,7 @@
     pass
 
 
-@override_settings(ANYMAIL={'WEBHOOK_AUTHORIZATION': 'username:password'})
+@override_settings(ANYMAIL={'WEBHOOK_SECRET': 'username:password'})
 class WebhookTestCase(AnymailTestMixin, SimpleTestCase):
     """Base for testing webhooks
 
@@ -111,7 +111,7 @@
         response = self.call_webhook()
         self.assertEqual(response.status_code, 400)
 
-    @override_settings(ANYMAIL={'WEBHOOK_AUTHORIZATION': ['cred1:pass1', 'cred2:pass2']})
+    @override_settings(ANYMAIL={'WEBHOOK_SECRET': ['cred1:pass1', 'cred2:pass2']})
     def test_supports_credential_rotation(self):
         """You can supply a list of basic auth credentials, and any is allowed"""
         self.set_basic_auth('cred1', 'pass1')
@@ -125,3 +125,9 @@
         self.set_basic_auth('baduser', 'wrongpassword')
         response = self.call_webhook()
         self.assertEqual(response.status_code, 400)
+
+    @override_settings(ANYMAIL={'WEBHOOK_AUTHORIZATION': "username:password"})
+    def test_deprecated_setting(self):
+        """The older WEBHOOK_AUTHORIZATION setting is still supported (for now)"""
+        response = self.call_webhook()
+        self.assertEqual(response.status_code, 200)
```
