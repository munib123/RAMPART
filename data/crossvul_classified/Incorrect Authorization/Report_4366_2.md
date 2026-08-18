# CrossVul Fix Pair: Incorrect Authorization in python
**Pair ID:** 4366_2
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4366_2`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```python
Lines 27-67 of the vulnerable file.

from jupyterhub.auth import LocalAuthenticator

from .oauth2 import OAuthLoginHandler, OAuthenticator


class CILogonLoginHandler(OAuthLoginHandler):
    """See http://www.cilogon.org/oidc for general information."""

    def authorize_redirect(self, *args, **kwargs):
        """Add idp, skin to redirect params"""
        extra_params = kwargs.setdefault('extra_params', {})
        if self.authenticator.idp:
            extra_params["selected_idp"] = self.authenticator.idp
        if self.authenticator.skin:
            extra_params["skin"] = self.authenticator.skin

        return super().authorize_redirect(*args, **kwargs)


class CILogonOAuthenticator(OAuthenticator):
    _deprecated_aliases = {
        "idp_whitelist": ("allowed_idps", "0.12.0"),
    }

    @observe(*list(_deprecated_aliases))
    def _deprecated_trait(self, change):
        super()._deprecated_trait(change)

    login_service = "CILogon"

    client_id_env = 'CILOGON_CLIENT_ID'
    client_secret_env = 'CILOGON_CLIENT_SECRET'
    login_handler = CILogonLoginHandler

    cilogon_host = Unicode(os.environ.get("CILOGON_HOST") or "cilogon.org", config=True)

    @default("authorize_url")
    def _authorize_url_default(self):
        return "https://%s/authorize" % self.cilogon_host

    @default("token_url")
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,13 +44,10 @@
 
 
 class CILogonOAuthenticator(OAuthenticator):
-    _deprecated_aliases = {
+    _deprecated_oauth_aliases = {
         "idp_whitelist": ("allowed_idps", "0.12.0"),
+        **OAuthenticator._deprecated_oauth_aliases,
     }
-
-    @observe(*list(_deprecated_aliases))
-    def _deprecated_trait(self, change):
-        super()._deprecated_trait(change)
 
     login_service = "CILogon"
 
```
