# CrossVul Fix Pair: Credentials Management Errors in python
**Pair ID:** 3792_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3792_0`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```python
Lines 144-186 of the vulnerable file.

        if not credentials and ec2Credentials:
            credentials = ec2Credentials

        if not 'access' in credentials:
            raise exception.Unauthorized(message='EC2 signature not supplied.')

        creds_ref = self._get_credentials(context,
                                          credentials['access'])
        self.check_signature(creds_ref, credentials)

        # TODO(termie): don't create new tokens every time
        # TODO(termie): this is copied from TokenController.authenticate
        token_id = uuid.uuid4().hex
        tenant_ref = self.identity_api.get_tenant(
                context=context,
                tenant_id=creds_ref['tenant_id'])
        user_ref = self.identity_api.get_user(
                context=context,
                user_id=creds_ref['user_id'])
        metadata_ref = self.identity_api.get_metadata(
                context=context,
                user_id=user_ref['id'],
                tenant_id=tenant_ref['id'])
        catalog_ref = self.catalog_api.get_catalog(
                context=context,
                user_id=user_ref['id'],
                tenant_id=tenant_ref['id'],
                    metadata=metadata_ref)

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

        # TODO(termie): make this a util function or something
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -161,9 +161,19 @@
                 context=context,
                 user_id=creds_ref['user_id'])
         metadata_ref = self.identity_api.get_metadata(
-                context=context,
-                user_id=user_ref['id'],
-                tenant_id=tenant_ref['id'])
+            context=context,
+            user_id=user_ref['id'],
+            tenant_id=tenant_ref['id'])
+
+        # TODO(termie): optimize this call at some point and put it into the
+        #               the return for metadata
+        # fill out the roles in the metadata
+        roles = metadata_ref.get('roles', [])
+        if not roles:
+            raise exception.Unauthorized(message='User not valid for tenant.')
+        roles_ref = [self.identity_api.get_role(context, role_id)
+                     for role_id in roles]
+
         catalog_ref = self.catalog_api.get_catalog(
                 context=context,
                 user_id=user_ref['id'],
@@ -175,13 +185,6 @@
                                         user=user_ref,
                                         tenant=tenant_ref,
                                         metadata=metadata_ref))
-
-        # TODO(termie): optimize this call at some point and put it into the
-        #               the return for metadata
-        # fill out the roles in the metadata
-        roles_ref = []
-        for role_id in metadata_ref.get('roles', []):
-            roles_ref.append(self.identity_api.get_role(context, role_id))
 
         # TODO(termie): make this a util function or something
         # TODO(termie): i don't think the ec2 middleware currently expects a
```
