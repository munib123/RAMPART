# CrossVul Fix Pair: Insertion of Sensitive Information into Log File in python
**Pair ID:** 18_2
**Vulnerability Class:** Insertion of Sensitive Information into Log File
**CWE:** CWE-532
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `18_2`)

## Vulnerability Information & PoC

## Description
Insertion of Sensitive Information into Log File - While logging all information may be helpful during development stages, it is important that logging levels be set appropriately before a product ships so that sensitive user data and system inform...

## Vulnerable Code
```python
Lines 7-47 of the vulnerable file.

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
        self.basic_auth = get_anymail_setting('webhook_authorization', default=[],
                                              kwargs=kwargs)  # no esp_name -- auth is shared between ESPs
        # Allow a single string:
        if isinstance(self.basic_auth, six.string_types):
            self.basic_auth = [self.basic_auth]
        if self.warn_if_no_basic_auth and len(self.basic_auth) < 1:
            warnings.warn(
                "Your Anymail webhooks are insecure and open to anyone on the web. "
                "You should set WEBHOOK_AUTHORIZATION in your ANYMAIL settings. "
                "See 'Securing webhooks' in the Anymail docs.",
                AnymailInsecureWebhookWarning)
        # noinspection PyArgumentList
        super(AnymailBasicAuthMixin, self).__init__(**kwargs)

    def validate_request(self, request):
        """If configured for webhook basic auth, validate request has correct auth."""
        if self.basic_auth:
            request_auth = get_request_basic_auth(request)
            # Use constant_time_compare to avoid timing attack on basic auth. (It's OK that any()
            # can terminate early: we're not trying to protect how many auth strings are allowed,
            # just the contents of each individual auth string.)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,15 +24,19 @@
     basic_auth = None  # (Declaring class attr allows override by kwargs in View.as_view.)
 
     def __init__(self, **kwargs):
-        self.basic_auth = get_anymail_setting('webhook_authorization', default=[],
+        self.basic_auth = get_anymail_setting('webhook_secret', default=[],
                                               kwargs=kwargs)  # no esp_name -- auth is shared between ESPs
+        if not self.basic_auth:
+            # Temporarily allow deprecated WEBHOOK_AUTHORIZATION setting
+            self.basic_auth = get_anymail_setting('webhook_authorization', default=[], kwargs=kwargs)
+
         # Allow a single string:
         if isinstance(self.basic_auth, six.string_types):
             self.basic_auth = [self.basic_auth]
         if self.warn_if_no_basic_auth and len(self.basic_auth) < 1:
             warnings.warn(
                 "Your Anymail webhooks are insecure and open to anyone on the web. "
-                "You should set WEBHOOK_AUTHORIZATION in your ANYMAIL settings. "
+                "You should set WEBHOOK_SECRET in your ANYMAIL settings. "
                 "See 'Securing webhooks' in the Anymail docs.",
                 AnymailInsecureWebhookWarning)
         # noinspection PyArgumentList
```
