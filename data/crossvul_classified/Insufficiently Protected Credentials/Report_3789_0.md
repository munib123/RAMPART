# CrossVul Fix Pair: Credentials Management Errors in python
**Pair ID:** 3789_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3789_0`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```python
Lines 421-461 of the vulnerable file.


        service_catalog = self._format_catalog(catalog_ref)
        token_data['access']['serviceCatalog'] = service_catalog

        if config.CONF.signing.token_format == 'UUID':
            token_id = uuid.uuid4().hex
        elif config.CONF.signing.token_format == 'PKI':

            token_id = cms.cms_sign_token(json.dumps(token_data),
                                          config.CONF.signing.certfile,
                                          config.CONF.signing.keyfile)
        else:
            raise exception.UnexpectedError(
                'Invalid value for token_format: %s.'
                '  Allowed values are PKI or UUID.' %
                config.CONF.signing.token_format)
        try:
            self.token_api.create_token(
                context, token_id, dict(key=token_id,
                                        id=token_id,
                                        user=user_ref,
                                        tenant=tenant_ref,
                                        metadata=metadata_ref))
        except Exception as e:
            # an identical token may have been created already.
            # if so, return the token_data as it is also identical
            try:
                self.token_api.get_token(context=context,
                                         token_id=token_id)
            except exception.TokenNotFound:
                raise e

        token_data['access']['token']['id'] = token_id

        return token_data

    def _get_token_ref(self, context, token_id, belongs_to=None):
        """Returns a token if a valid one exists.

        Optionally, limited to a token owned by a specific tenant.

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -438,6 +438,7 @@
             self.token_api.create_token(
                 context, token_id, dict(key=token_id,
                                         id=token_id,
+                                        expires=auth_token_data['expires'],
                                         user=user_ref,
                                         tenant=tenant_ref,
                                         metadata=metadata_ref))
```
