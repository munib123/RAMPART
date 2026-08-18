# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3691_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3691_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 334-374 of the vulnerable file.

            tenant_ref = self.identity_api.get_tenant(context=context,
                                                      tenant_id=tenant_id)
            if tenant_ref:
                metadata_ref = self.identity_api.get_metadata(
                        context=context,
                        user_id=user_ref['id'],
                        tenant_id=tenant_ref['id'])
                catalog_ref = self.catalog_api.get_catalog(
                        context=context,
                        user_id=user_ref['id'],
                        tenant_id=tenant_ref['id'],
                        metadata=metadata_ref)
            else:
                metadata_ref = {}
                catalog_ref = {}

            token_ref = self.token_api.create_token(
                    context, token_id, dict(id=token_id,
                                            user=user_ref,
                                            tenant=tenant_ref,
                                            metadata=metadata_ref))

        # TODO(termie): optimize this call at some point and put it into the
        #               the return for metadata
        # fill out the roles in the metadata
        roles_ref = []
        for role_id in metadata_ref.get('roles', []):
            roles_ref.append(self.identity_api.get_role(context, role_id))
        logging.debug('TOKEN_REF %s', token_ref)
        return self._format_authenticate(token_ref, roles_ref, catalog_ref)

    def _get_token_ref(self, context, token_id, belongs_to=None):
        """Returns a token if a valid one exists.

        Optionally, limited to a token owned by a specific tenant.

        """
        # TODO(termie): this stuff should probably be moved to middleware
        self.assert_admin(context)

        token_ref = self.token_api.get_token(context=context,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -351,7 +351,8 @@
                     context, token_id, dict(id=token_id,
                                             user=user_ref,
                                             tenant=tenant_ref,
-                                            metadata=metadata_ref))
+                                            metadata=metadata_ref,
+                                            expires=old_token_ref['expires']))
 
         # TODO(termie): optimize this call at some point and put it into the
         #               the return for metadata
```
