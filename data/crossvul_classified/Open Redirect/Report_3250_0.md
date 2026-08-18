# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 3250_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3250_0`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 223-263 of the vulnerable file.


        if not self.acl.seted:
            self._setup_acl()

        _roles = set()
        _methods = {'*', method}
        _resources = {None, resource}

        _roles.add(anonymous)

        _roles.update(roles)

        for r, m, res in itertools.product(_roles, _methods, _resources):
            if self.acl.is_allowed(r.name, m, res):
                return True

        return False

    def _deny_hook(self, resource=None):
        app = self.get_app()
        if current_user.is_authenticated():
            status = 403
        else:
            status = 401
        #abort(status)

        if app.config.get('FRONTED_BY_NGINX'):
                url = "https://{}:{}{}".format(app.config.get('FQDN'), app.config.get('NGINX_PORT'), '/login')
        else:
                url = "http://{}:{}{}".format(app.config.get('FQDN'), app.config.get('API_PORT'), '/login')
        if current_user.is_authenticated():
            auth_dict = {
                "authenticated": True,
                "user": current_user.email,
                "roles": current_user.role,
            }
        else:
            auth_dict = {
                "authenticated": False,
                "user": None,
                "url": url
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -240,7 +240,7 @@
 
     def _deny_hook(self, resource=None):
         app = self.get_app()
-        if current_user.is_authenticated():
+        if current_user.is_authenticated:
             status = 403
         else:
             status = 401
@@ -250,7 +250,7 @@
                 url = "https://{}:{}{}".format(app.config.get('FQDN'), app.config.get('NGINX_PORT'), '/login')
         else:
                 url = "http://{}:{}{}".format(app.config.get('FQDN'), app.config.get('API_PORT'), '/login')
-        if current_user.is_authenticated():
+        if current_user.is_authenticated:
             auth_dict = {
                 "authenticated": True,
                 "user": current_user.email,
```
