# CrossVul Fix Pair: Incorrect Authorization in python
**Pair ID:** 4366_1
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4366_1`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```python
Lines 11-51 of the vulnerable file.

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Set, default, observe

from .oauth2 import OAuthLoginHandler, OAuthenticator


def _api_headers(access_token):
    return {
        "Accept": "application/json",
        "User-Agent": "JupyterHub",
        "Authorization": "Bearer {}".format(access_token),
    }


class BitbucketOAuthenticator(OAuthenticator):

    _deprecated_aliases = {
        "team_whitelist": ("allowed_teams", "0.12.0"),
    }

    @observe(*list(_deprecated_aliases))
    def _deprecated_trait(self, change):
        super()._deprecated_trait(change)

    login_service = "Bitbucket"
    client_id_env = 'BITBUCKET_CLIENT_ID'
    client_secret_env = 'BITBUCKET_CLIENT_SECRET'

    @default("authorize_url")
    def _authorize_url_default(self):
        return "https://bitbucket.org/site/oauth2/authorize"

    @default("token_url")
    def _token_url_default(self):
        return "https://bitbucket.org/site/oauth2/access_token"

    team_whitelist = Set(help="Deprecated, use `BitbucketOAuthenticator.allowed_teams`", config=True,)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,13 +28,10 @@
 
 class BitbucketOAuthenticator(OAuthenticator):
 
-    _deprecated_aliases = {
+    _deprecated_oauth_aliases = {
         "team_whitelist": ("allowed_teams", "0.12.0"),
+        **OAuthenticator._deprecated_oauth_aliases,
     }
-
-    @observe(*list(_deprecated_aliases))
-    def _deprecated_trait(self, change):
-        super()._deprecated_trait(change)
 
     login_service = "Bitbucket"
     client_id_env = 'BITBUCKET_CLIENT_ID'
```
