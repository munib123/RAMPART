# CrossVul Fix Pair: Improper Authentication in python
**Pair ID:** 3757_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3757_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```python
Lines 440-480 of the vulnerable file.

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
        if tenant_id is None:
            raise exception.NotImplemented(message='User roles not supported: '
                                                   'tenant ID required')

        user = self.identity_api.get_user(context, user_id)
        if user is None:
            raise exception.UserNotFound(user_id=user_id)
        tenant = self.identity_api.get_tenant(context, tenant_id)
        if tenant is None:
            raise exception.TenantNotFound(tenant_id=tenant_id)

        roles = self.identity_api.get_roles_for_user_and_tenant(
                context, user_id, tenant_id)
        return {'roles': [self.identity_api.get_role(context, x)
                          for x in roles]}

    # CRUD extension
    def get_role(self, context, role_id):
        self.assert_admin(context)
        role_ref = self.identity_api.get_role(context, role_id)
        if not role_ref:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -457,6 +457,7 @@
         not implementing them in hopes that the idea will die off.
 
         """
+        self.assert_admin(context)
         if tenant_id is None:
             raise exception.NotImplemented(message='User roles not supported: '
                                                    'tenant ID required')
```
