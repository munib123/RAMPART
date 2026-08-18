# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3724_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3724_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 419-459 of the vulnerable file.

                # backends that can't list tokens for users
                LOG.warning('User %s status has changed, but existing tokens '
                            'remain valid' % user_id)
        return {'user': user_ref}

    def delete_user(self, context, user_id):
        self.assert_admin(context)
        if self.identity_api.get_user(context, user_id) is None:
            raise exception.UserNotFound(user_id=user_id)

        self.identity_api.delete_user(context, user_id)

    def set_user_enabled(self, context, user_id, user):
        return self.update_user(context, user_id, user)

    def set_user_password(self, context, user_id, user):
        return self.update_user(context, user_id, user)

    def update_user_tenant(self, context, user_id, user):
        """Update the default tenant."""
        # ensure that we're a member of that tenant
        tenant_id = user.get('tenantId')
        self.identity_api.add_user_to_tenant(context, tenant_id, user_id)
        return self.update_user(context, user_id, user)


class RoleController(wsgi.Application):
    def __init__(self):
        self.identity_api = Manager()
        self.token_api = token.Manager()
        self.policy_api = policy.Manager()
        super(RoleController, self).__init__()

    # COMPAT(essex-3)
    def get_user_roles(self, context, user_id, tenant_id=None):
        """Get the roles for a user and tenant pair.

        Since we're trying to ignore the idea of user-only roles we're
        not implementing them in hopes that the idea will die off.

        """
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -436,6 +436,7 @@
 
     def update_user_tenant(self, context, user_id, user):
         """Update the default tenant."""
+        self.assert_admin(context)
         # ensure that we're a member of that tenant
         tenant_id = user.get('tenantId')
         self.identity_api.add_user_to_tenant(context, tenant_id, user_id)
```
