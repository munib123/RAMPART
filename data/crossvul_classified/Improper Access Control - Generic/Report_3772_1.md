# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3772_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3772_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 43-83 of the vulnerable file.


    def __init__(self, *args, **kwargs):
        pass

    def connect(self):
        return True

    def close(self):
        return True

    def request(self, method, url, body=None, headers=None):
        self.req = webob.Request.blank("/" + url.lstrip("/"))
        self.req.method = method
        if headers:
            self.req.headers = headers
        if body:
            self.req.body = body

    def getresponse(self):
        mapper = routes.Mapper()
        api = context.UnauthenticatedContextMiddleware(rserver.API(mapper))
        webob_res = self.req.get_response(api)

        return utils.FakeHTTPResponse(status=webob_res.status_int,
                                      headers=webob_res.headers,
                                      data=webob_res.body)


def stub_out_registry_and_store_server(stubs, base_dir):
    """
    Mocks calls to 127.0.0.1 on 9191 and 9292 for testing so
    that a real Glance server does not need to be up and
    running
    """

    class FakeSocket(object):

        def __init__(self, *args, **kwargs):
            pass

        def fileno(self):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,7 +60,13 @@
 
     def getresponse(self):
         mapper = routes.Mapper()
-        api = context.UnauthenticatedContextMiddleware(rserver.API(mapper))
+        server = rserver.API(mapper)
+        # NOTE(markwash): we need to pass through context auth information if
+        # we have it.
+        if 'X-Auth-Token' in self.req.headers:
+            api = utils.FakeAuthMiddleware(server)
+        else:
+            api = context.UnauthenticatedContextMiddleware(server)
         webob_res = self.req.get_response(api)
 
         return utils.FakeHTTPResponse(status=webob_res.status_int,
```
