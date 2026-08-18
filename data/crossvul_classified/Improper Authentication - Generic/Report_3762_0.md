# CrossVul Fix Pair: Improper Authentication in python
**Pair ID:** 3762_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3762_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```python
Lines 263-303 of the vulnerable file.


            # more compat
            tenant_id = auth.get('tenantId', None)
            if tenant_name:
                tenant_ref = self.identity_api.get_tenant_by_name(
                        context=context, tenant_name=tenant_name)
                if tenant_ref:
                    tenant_id = tenant_ref['id']

            try:
                auth_info = self.identity_api.authenticate(context=context,
                                                           user_id=user_id,
                                                           password=password,
                                                           tenant_id=tenant_id)
                (user_ref, tenant_ref, metadata_ref) = auth_info

                # If the user is disabled don't allow them to authenticate
                if not user_ref.get('enabled', True):
                    LOG.warning('User %s is disabled' % user_id)
                    raise exception.Unauthorized()
            except AssertionError as e:
                raise exception.Unauthorized(e.message)

            token_ref = self.token_api.create_token(
                    context, token_id, dict(id=token_id,
                                            user=user_ref,
                                            tenant=tenant_ref,
                                            metadata=metadata_ref))
            if tenant_ref:
                catalog_ref = self.catalog_api.get_catalog(
                        context=context,
                        user_id=user_ref['id'],
                        tenant_id=tenant_ref['id'],
                        metadata=metadata_ref)
            else:
                catalog_ref = {}

        elif 'token' in auth:
            token = auth['token'].get('id', None)

            tenant_name = auth.get('tenantName')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -280,6 +280,11 @@
                 if not user_ref.get('enabled', True):
                     LOG.warning('User %s is disabled' % user_id)
                     raise exception.Unauthorized()
+
+                # If the tenant is disabled don't allow them to authenticate
+                if tenant_ref and not tenant_ref.get('enabled', True):
+                    LOG.warning('Tenant %s is disabled' % tenant_id)
+                    raise exception.Unauthorized()
             except AssertionError as e:
                 raise exception.Unauthorized(e.message)
 
@@ -333,6 +338,12 @@
 
             tenant_ref = self.identity_api.get_tenant(context=context,
                                                       tenant_id=tenant_id)
+
+            # If the tenant is disabled don't allow them to authenticate
+            if tenant_ref and not tenant_ref.get('enabled', True):
+                LOG.warning('Tenant %s is disabled' % tenant_id)
+                raise exception.Unauthorized()
+
             if tenant_ref:
                 metadata_ref = self.identity_api.get_metadata(
                         context=context,
```
