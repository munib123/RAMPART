# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3771_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3771_3`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 355-395 of the vulnerable file.


    def process_request(self, req):
        auth_tok = req.headers.get('X-Auth-Token')
        user = None
        tenant = None
        roles = []
        if auth_tok:
            user, tenant, role = auth_tok.split(':')
            if tenant.lower() == 'none':
                tenant = None
            roles = [role]
            req.headers['X-User-Id'] = user
            req.headers['X-Tenant-Id'] = tenant
            req.headers['X-Roles'] = role
            req.headers['X-Identity-Status'] = 'Confirmed'
        kwargs = {
            'user': user,
            'tenant': tenant,
            'roles': roles,
            'is_admin': self.is_admin,
        }

        req.context = context.RequestContext(**kwargs)


class FakeHTTPResponse(object):
    def __init__(self, status=200, headers=None, data=None, *args, **kwargs):
        data = data or 'I am a teapot, short and stout\n'
        self.data = StringIO.StringIO(data)
        self.read = self.data.read
        self.status = status
        self.headers = headers or {'content-length': len(data)}

    def getheader(self, name, default=None):
        return self.headers.get(name.lower(), default)

    def getheaders(self):
        return self.headers or {}

    def read(self, amt):
        self.data.read(amt)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -372,6 +372,7 @@
             'tenant': tenant,
             'roles': roles,
             'is_admin': self.is_admin,
+            'auth_tok': auth_tok,
         }
 
         req.context = context.RequestContext(**kwargs)
```
