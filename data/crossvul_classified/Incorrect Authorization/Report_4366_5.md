# CrossVul Fix Pair: Incorrect Authorization in python
**Pair ID:** 4366_5
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4366_5`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```python
Lines 13-53 of the vulnerable file.

from tornado.auth import GoogleOAuth2Mixin
from tornado.web import HTTPError

from traitlets import Dict, Unicode, List, default, validate, observe

from jupyterhub.crypto import decrypt, EncryptionUnavailable, InvalidToken
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join

from .oauth2 import OAuthLoginHandler, OAuthCallbackHandler, OAuthenticator

def check_user_in_groups(member_groups, allowed_groups):
    # Check if user is a member of any group in the allowed groups
    if any(g in member_groups for g in allowed_groups):
        return True  # user _is_ in group
    else:
        return False


class GoogleOAuthenticator(OAuthenticator, GoogleOAuth2Mixin):
    _deprecated_aliases = {
        "google_group_whitelist": ("allowed_google_groups", "0.12.0"),
    }

    @observe(*list(_deprecated_aliases))
    def _deprecated_trait(self, change):
        super()._deprecated_trait(change)

    google_api_url = Unicode("https://www.googleapis.com", config=True)

    @default('google_api_url')
    def _google_api_url(self):
        """get default google apis url from env"""
        google_api_url = os.getenv('GOOGLE_API_URL')

        # default to googleapis.com
        if not google_api_url:
            google_api_url = 'https://www.googleapis.com'

        return google_api_url

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,13 +30,10 @@
 
 
 class GoogleOAuthenticator(OAuthenticator, GoogleOAuth2Mixin):
-    _deprecated_aliases = {
+    _deprecated_oauth_aliases = {
         "google_group_whitelist": ("allowed_google_groups", "0.12.0"),
+        **OAuthenticator._deprecated_oauth_aliases,
     }
-
-    @observe(*list(_deprecated_aliases))
-    def _deprecated_trait(self, change):
-        super()._deprecated_trait(change)
 
     google_api_url = Unicode("https://www.googleapis.com", config=True)
 
```
