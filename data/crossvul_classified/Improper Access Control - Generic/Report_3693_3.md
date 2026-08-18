# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3693_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3693_3`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 70-97 of the vulnerable file.

                metadata=metadata_ref
            }

        :type data: dict
        :returns: token_ref or None.

        """
        raise exception.NotImplemented()

    def delete_token(self, token_id):
        """Deletes a token by id.

        :param token_id: identity of the token
        :type token_id: string
        :returns: None.
        :raises: keystone.exception.TokenNotFound

        """
        raise exception.NotImplemented()

    def _get_default_expire_time(self):
        """Determine when a token should expire based on the config.

        :returns: a naive utc datetime.datetime object

        """
        expire_delta = datetime.timedelta(seconds=CONF.token.expiration)
        return datetime.datetime.utcnow() + expire_delta
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -87,6 +87,16 @@
         """
         raise exception.NotImplemented()
 
+    def list_tokens(self, user_id):
+        """Returns a list of current token_id's for a user
+
+        :param user_id: identity of the user
+        :type user_id: string
+        :returns: list of token_id's
+
+        """
+        raise exception.NotImplemented()
+
     def _get_default_expire_time(self):
         """Determine when a token should expire based on the config.
 
```
