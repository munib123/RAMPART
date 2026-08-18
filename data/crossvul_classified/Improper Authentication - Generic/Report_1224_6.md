# CrossVul Fix Pair: Improper Authentication in python
**Pair ID:** 1224_6
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1224_6`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```python
Lines 194-234 of the vulnerable file.

        return None

class EmailAuthBackend(ZulipAuthMixin):
    """
    Email+Password Authentication Backend (the default).

    Allows a user to sign in using an email/password pair.
    """

    def authenticate(self, *, username: str, password: str,
                     realm: Realm,
                     return_data: Optional[Dict[str, Any]]=None) -> Optional[UserProfile]:
        """ Authenticate a user based on email address as the user name. """
        if not password_auth_enabled(realm):
            if return_data is not None:
                return_data['password_auth_disabled'] = True
            return None
        if not email_auth_enabled(realm):
            if return_data is not None:
                return_data['email_auth_disabled'] = True
            return None

        user_profile = common_get_active_user(username, realm, return_data=return_data)
        if user_profile is None:
            return None
        if user_profile.check_password(password):
            return user_profile
        return None

class ZulipRemoteUserBackend(RemoteUserBackend):
    """Authentication backend that reads the Apache REMOTE_USER variable.
    Used primarily in enterprise environments with an SSO solution
    that has an Apache REMOTE_USER integration.  For manual testing, see

      https://zulip.readthedocs.io/en/latest/production/authentication-methods.html

    See also remote_user_sso in zerver/views/auth.py.
    """
    create_unknown_user = False

    def authenticate(self, *, remote_user: str, realm: Realm,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -211,6 +211,11 @@
         if not email_auth_enabled(realm):
             if return_data is not None:
                 return_data['email_auth_disabled'] = True
+            return None
+        if password == "":
+            # Never allow an empty password.  This is defensive code;
+            # a user having password "" should only be possible
+            # through a bug somewhere else.
             return None
 
         user_profile = common_get_active_user(username, realm, return_data=return_data)
```
