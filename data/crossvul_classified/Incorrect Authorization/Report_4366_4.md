# CrossVul Fix Pair: Incorrect Authorization in python
**Pair ID:** 4366_4
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4366_4`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```python
Lines 20-60 of the vulnerable file.

from jupyterhub.auth import LocalAuthenticator

from traitlets import Set, CUnicode, Unicode, default, observe

from .oauth2 import OAuthLoginHandler, OAuthenticator


def _api_headers(access_token):
    return {
        "Accept": "application/json",
        "User-Agent": "JupyterHub",
        "Authorization": "Bearer {}".format(access_token),
    }


class GitLabOAuthenticator(OAuthenticator):
    # see gitlab_scopes.md for details about scope config
    # set scopes via config, e.g.
    # c.GitLabOAuthenticator.scope = ['read_user']

    _deprecated_aliases = {
        "gitlab_group_whitelist": ("allowed_gitlab_groups", "0.12.0"),
        "gitlab_project_id_whitelist": ("allowed_project_ids", "0.12.0")
    }

    @observe(*list(_deprecated_aliases))
    def _deprecated_trait(self, change):
        super()._deprecated_trait(change)

    login_service = "GitLab"

    client_id_env = 'GITLAB_CLIENT_ID'
    client_secret_env = 'GITLAB_CLIENT_SECRET'

    gitlab_url = Unicode("https://gitlab.com", config=True)

    @default("gitlab_url")
    def _default_gitlab_url(self):
        """get default gitlab url from env"""
        gitlab_url = os.getenv('GITLAB_URL')
        gitlab_host = os.getenv('GITLAB_HOST')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,14 +37,11 @@
     # set scopes via config, e.g.
     # c.GitLabOAuthenticator.scope = ['read_user']
 
-    _deprecated_aliases = {
+    _deprecated_oauth_aliases = {
         "gitlab_group_whitelist": ("allowed_gitlab_groups", "0.12.0"),
-        "gitlab_project_id_whitelist": ("allowed_project_ids", "0.12.0")
+        "gitlab_project_id_whitelist": ("allowed_project_ids", "0.12.0"),
+        **OAuthenticator._deprecated_oauth_aliases,
     }
-
-    @observe(*list(_deprecated_aliases))
-    def _deprecated_trait(self, change):
-        super()._deprecated_trait(change)
 
     login_service = "GitLab"
 
```
