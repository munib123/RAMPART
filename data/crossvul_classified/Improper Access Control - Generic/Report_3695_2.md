# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3695_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3695_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 27-46 of the vulnerable file.

    def get_token(self, token_id):
        token = self.db.get('token-%s' % token_id)
        if (token and (token['expires'] is None
                       or token['expires'] > datetime.datetime.utcnow())):
            return token
        else:
            raise exception.TokenNotFound(token_id=token_id)

    def create_token(self, token_id, data):
        data_copy = copy.deepcopy(data)
        if 'expires' not in data:
            data_copy['expires'] = self._get_default_expire_time()
        self.db.set('token-%s' % token_id, data_copy)
        return copy.deepcopy(data_copy)

    def delete_token(self, token_id):
        try:
            return self.db.delete('token-%s' % token_id)
        except KeyError:
            raise exception.TokenNotFound(token_id=token_id)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,3 +44,18 @@
             return self.db.delete('token-%s' % token_id)
         except KeyError:
             raise exception.TokenNotFound(token_id=token_id)
+
+    def list_tokens(self, user_id):
+        tokens = []
+        now = datetime.datetime.utcnow()
+        for token, user_ref in self.db.items():
+            if not token.startswith('token-'):
+                continue
+            if 'user' not in user_ref:
+                continue
+            if user_ref['user'].get('id') != user_id:
+                continue
+            if user_ref.get('expires') and user_ref.get('expires') < now:
+                continue
+            tokens.append(token.split('-', 1)[1])
+        return tokens
```
