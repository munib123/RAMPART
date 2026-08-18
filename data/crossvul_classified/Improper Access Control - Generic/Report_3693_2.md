# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3693_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3693_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 64-83 of the vulnerable file.

        token_ref = TokenModel.from_dict(data_copy)
        token_ref.id = token_id

        session = self.get_session()
        with session.begin():
            session.add(token_ref)
            session.flush()
        return token_ref.to_dict()

    def delete_token(self, token_id):
        session = self.get_session()
        token_ref = session.query(TokenModel)\
                                .filter_by(id=token_id)\
                                .first()
        if not token_ref:
            raise exception.TokenNotFound(token_id=token_id)

        with session.begin():
            session.delete(token_ref)
            session.flush()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -81,3 +81,17 @@
         with session.begin():
             session.delete(token_ref)
             session.flush()
+
+    def list_tokens(self, user_id):
+        session = self.get_session()
+        tokens = []
+        now = datetime.datetime.utcnow()
+        for token_ref in session.query(TokenModel)\
+                                      .filter(TokenModel.expires > now):
+            token_ref_dict = token_ref.to_dict()
+            if 'user' not in token_ref_dict:
+                continue
+            if token_ref_dict['user'].get('id') != user_id:
+                continue
+            tokens.append(token_ref['id'])
+        return tokens
```
