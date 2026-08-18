# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 1731_1
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1731_1`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 1524-1564 of the vulnerable file.

                                    ('?_next=' + urllib.quote(current.request.env.http_web2py_component_location))
                              if current.request.env.http_web2py_component_location else ''),
                            ' to view this content.',
                            _class='not-authorized alert alert-block'))
        messages.lock_keys = True

        # for "remember me" option
        response = current.response
        if auth and auth.remember_me:
            # when user wants to be logged in for longer
            response.session_cookie_expires = auth.expiration
        if signature:
            self.define_signature()
        else:
            self.signature = None

    def get_vars_next(self):
        next = current.request.vars._next
        if isinstance(next, (list, tuple)):
            next = next[0]
        return next

    def _get_user_id(self):
        """accessor for auth.user_id"""
        return self.user and self.user.id or None

    user_id = property(_get_user_id, doc="user.id or None")

    def table_user(self):
        return self.db[self.settings.table_user_name]

    def table_group(self):
        return self.db[self.settings.table_group_name]

    def table_membership(self):
        return self.db[self.settings.table_membership_name]

    def table_permission(self):
        return self.db[self.settings.table_permission_name]

    def table_event(self):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1541,6 +1541,12 @@
         next = current.request.vars._next
         if isinstance(next, (list, tuple)):
             next = next[0]
+        if next and self.settings.prevent_open_redirect_attacks:
+            # Prevent an attacker from adding an arbitrary url after the
+            # _next variable in the request.
+            items = next.split('/')
+            if '//' in next and items[2] != current.request.env.http_host:
+                next = None            
         return next
 
     def _get_user_id(self):
@@ -2513,10 +2519,6 @@
 
         ### use session for federated login
         snext = self.get_vars_next()
-        if snext and self.settings.prevent_open_redirect_attacks:
-            items = snext.split('/')
-            if '//' in snext and items[2] != request.env.http_host:
-                snext = None
 
         if snext:
             session._auth_next = snext
```
