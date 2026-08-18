# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 3250_2
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3250_2`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 127-167 of the vulnerable file.

    'prefix': fields.String,
    'notes': fields.String,
}

AUDITORSETTING_FIELDS = {
    'id': fields.Integer,
    'disabled': fields.Boolean,
    'issue_text': fields.String
}

ITEM_LINK_FIELDS = {
    'id': fields.Integer,
    'name': fields.String
}

class AuthenticatedService(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(AuthenticatedService, self).__init__()
        self.auth_dict = dict()
        if current_user.is_authenticated():
            roles_marshal = []
            for role in current_user.roles:
                roles_marshal.append(marshal(role.__dict__, ROLE_FIELDS))

            roles_marshal.append({"name": current_user.role})

            for role in RBACRole.roles[current_user.role].get_parents():
                roles_marshal.append({"name": role.name})

            self.auth_dict = {
                "authenticated": True,
                "user": current_user.email,
                "roles": roles_marshal
            }
        else:
            if app.config.get('FRONTED_BY_NGINX'):
                url = "https://{}:{}{}".format(app.config.get('FQDN'), app.config.get('NGINX_PORT'), '/login')
            else:
                url = "http://{}:{}{}".format(app.config.get('FQDN'), app.config.get('API_PORT'), '/login')
            self.auth_dict = {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -144,7 +144,7 @@
         self.reqparse = reqparse.RequestParser()
         super(AuthenticatedService, self).__init__()
         self.auth_dict = dict()
-        if current_user.is_authenticated():
+        if current_user.is_authenticated:
             roles_marshal = []
             for role in current_user.roles:
                 roles_marshal.append(marshal(role.__dict__, ROLE_FIELDS))
```
