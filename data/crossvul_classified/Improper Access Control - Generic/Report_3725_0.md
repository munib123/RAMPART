# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3725_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3725_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 498-538 of the vulnerable file.

                    self.token_api.delete_token(context, token_id)
            except exception.NotImplemented:
                # The users status has been changed but tokens remain valid for
                # backends that can't list tokens for users
                LOG.warning('User %s status has changed, but existing tokens '
                            'remain valid' % user_id)
        return {'user': user_ref}

    def delete_user(self, context, user_id):
        self.assert_admin(context)
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
@@ -515,6 +515,7 @@
 
     def update_user_tenant(self, context, user_id, user):
         """Update the default tenant."""
+        self.assert_admin(context)
         # ensure that we're a member of that tenant
         tenant_id = user.get('tenantId')
         self.identity_api.add_user_to_tenant(context, tenant_id, user_id)
```
