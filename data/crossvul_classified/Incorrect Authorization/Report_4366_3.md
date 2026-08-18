# CrossVul Fix Pair: Incorrect Authorization in python
**Pair ID:** 4366_3
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4366_3`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```python
Lines 20-60 of the vulnerable file.

from traitlets import List, Set, Unicode, default, observe

from .common import next_page_from_links
from .oauth2 import OAuthLoginHandler, OAuthenticator


def _api_headers(access_token):
    return {
        "Accept": "application/json",
        "User-Agent": "JupyterHub",
        "Authorization": "token {}".format(access_token),
    }


class GitHubOAuthenticator(OAuthenticator):

    # see github_scopes.md for details about scope config
    # set scopes via config, e.g.
    # c.GitHubOAuthenticator.scope = ['read:org']

    _deprecated_aliases = {
        "github_organization_whitelist": ("allowed_organizations", "0.12.0"),
    }

    @observe(*list(_deprecated_aliases))
    def _deprecated_trait(self, change):
        super()._deprecated_trait(change)

    login_service = "GitHub"

    github_url = Unicode("https://github.com", config=True)

    @default("github_url")
    def _github_url_default(self):
        github_url = os.environ.get("GITHUB_URL")
        if not github_url:
            # fallback on older GITHUB_HOST config,
            # treated the same as GITHUB_URL
            host = os.environ.get("GITHUB_HOST")
            if host:
                if os.environ.get("GITHUB_HTTP"):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,13 +37,10 @@
     # set scopes via config, e.g.
     # c.GitHubOAuthenticator.scope = ['read:org']
 
-    _deprecated_aliases = {
+    _deprecated_oauth_aliases = {
         "github_organization_whitelist": ("allowed_organizations", "0.12.0"),
+        **OAuthenticator._deprecated_oauth_aliases,
     }
-
-    @observe(*list(_deprecated_aliases))
-    def _deprecated_trait(self, change):
-        super()._deprecated_trait(change)
 
     login_service = "GitHub"
 
```
