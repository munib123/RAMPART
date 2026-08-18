# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3694_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3694_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 391-431 of the vulnerable file.

        tenant_id = user.get('tenantId', None)
        if (tenant_id is not None
                and self.identity_api.get_tenant(context, tenant_id) is None):
            raise exception.TenantNotFound(tenant_id=tenant_id)
        user_id = uuid.uuid4().hex
        user_ref = user.copy()
        user_ref['id'] = user_id
        new_user_ref = self.identity_api.create_user(
                context, user_id, user_ref)
        if tenant_id:
            self.identity_api.add_user_to_tenant(context, tenant_id, user_id)
        return {'user': new_user_ref}

    def update_user(self, context, user_id, user):
        # NOTE(termie): this is really more of a patch than a put
        self.assert_admin(context)
        if self.identity_api.get_user(context, user_id) is None:
            raise exception.UserNotFound(user_id=user_id)

        user_ref = self.identity_api.update_user(context, user_id, user)
        return {'user': user_ref}

    def delete_user(self, context, user_id):
        self.assert_admin(context)
        if self.identity_api.get_user(context, user_id) is None:
            raise exception.UserNotFound(user_id=user_id)

        self.identity_api.delete_user(context, user_id)

    def set_user_enabled(self, context, user_id, user):
        return self.update_user(context, user_id, user)

    def set_user_password(self, context, user_id, user):
        user_ref = self.update_user(context, user_id, user)
        try:
            for token_id in self.token_api.list_tokens(context, user_id):
                self.token_api.delete_token(context, token_id)
        except exception.NotImplemented:
            # The password has been changed but tokens remain valid for
            # backends that can't list tokens for users
            LOG.warning('Password changed for %s, but existing tokens remain '
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -408,6 +408,17 @@
             raise exception.UserNotFound(user_id=user_id)
 
         user_ref = self.identity_api.update_user(context, user_id, user)
+
+        # If the password was changed or the user was disabled we clear tokens
+        if user.get('password') or user.get('enabled', True) == False:
+            try:
+                for token_id in self.token_api.list_tokens(context, user_id):
+                    self.token_api.delete_token(context, token_id)
+            except exception.NotImplemented:
+                # The users status has been changed but tokens remain valid for
+                # backends that can't list tokens for users
+                LOG.warning('User %s status has changed, but existing tokens '
+                            'remain valid' % user_id)
         return {'user': user_ref}
 
     def delete_user(self, context, user_id):
@@ -421,16 +432,7 @@
         return self.update_user(context, user_id, user)
 
     def set_user_password(self, context, user_id, user):
-        user_ref = self.update_user(context, user_id, user)
-        try:
-            for token_id in self.token_api.list_tokens(context, user_id):
-                self.token_api.delete_token(context, token_id)
-        except exception.NotImplemented:
-            # The password has been changed but tokens remain valid for
-            # backends that can't list tokens for users
-            LOG.warning('Password changed for %s, but existing tokens remain '
-                        'valid' % user_id)
-        return user_ref
+        return self.update_user(context, user_id, user)
 
     def update_user_tenant(self, context, user_id, user):
         """Update the default tenant."""
```
