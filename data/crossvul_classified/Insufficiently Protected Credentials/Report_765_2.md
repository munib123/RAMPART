# CrossVul Fix Pair: Insufficiently Protected Credentials in python
**Pair ID:** 765_2
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `765_2`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```python
Lines 14-43 of the vulnerable file.

    def authenticate(self, request, username=None, code=None, **kwargs):
        if username is None:
            username = kwargs.get(get_user_model().USERNAME_FIELD)

        if not username or not code:
            return

        try:
            user = get_user_model()._default_manager.get_by_natural_key(username)

            if not self.user_can_authenticate(user):
                return

            timeout = getattr(settings, 'NOPASSWORD_LOGIN_CODE_TIMEOUT', 900)
            timestamp = timezone.now() - timedelta(seconds=timeout)

            # We don't delete the login code when authenticating,
            # as that is done during validation of the login form
            # and validation should not have any side effects.
            # It is the responsibility of the view/form to delete the token
            # as soon as the login was successfull.
            user.login_code = LoginCode.objects.get(user=user, code=code, timestamp__gt=timestamp)

            return user

        except (get_user_model().DoesNotExist, LoginCode.DoesNotExist):
            return

    def send_login_code(self, code, context, **kwargs):
        raise NotImplementedError
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,10 +31,13 @@
             # as that is done during validation of the login form
             # and validation should not have any side effects.
             # It is the responsibility of the view/form to delete the token
-            # as soon as the login was successfull.
-            user.login_code = LoginCode.objects.get(user=user, code=code, timestamp__gt=timestamp)
+            # as soon as the login was successful.
 
-            return user
+            for c in LoginCode.objects.filter(user=user, timestamp__gt=timestamp):
+                if c.code == code:
+                    user.login_code = c
+                    return user
+            return
 
         except (get_user_model().DoesNotExist, LoginCode.DoesNotExist):
             return
```
