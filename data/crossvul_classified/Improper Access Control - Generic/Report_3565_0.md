# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3565_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3565_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 470-511 of the vulnerable file.

        self.deserializer = deserializer or RequestDeserializer()
        self.serializer = serializer or ResponseSerializer()

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, request):
        """WSGI method that controls (de)serialization and method dispatch."""

        LOG.info("%(method)s %(url)s" % {"method": request.method,
                                          "url": request.url})

        try:
            action, args, accept = self.deserializer.deserialize(request)
        except exception.InvalidContentType:
            msg = _("Unsupported Content-Type")
            return faults.Fault(webob.exc.HTTPBadRequest(explanation=msg))
        except exception.MalformedRequestBody:
            msg = _("Malformed request body")
            return faults.Fault(webob.exc.HTTPBadRequest(explanation=msg))

        project_id = args.pop("project_id", None)
        if 'nova.context' in request.environ and project_id:
            request.environ['nova.context'].project_id = project_id

        try:
            action_result = self.dispatch(request, action, args)
        except faults.Fault as ex:
            LOG.info(_("Fault thrown: %s"), unicode(ex))
            action_result = ex
        except webob.exc.HTTPException as ex:
            LOG.info(_("HTTP exception thrown: %s"), unicode(ex))
            action_result = faults.Fault(ex)

        if type(action_result) is dict or action_result is None:
            response = self.serializer.serialize(action_result,
                                                 accept,
                                                 action=action)
        else:
            response = action_result

        try:
            msg_dict = dict(url=request.url, status=response.status_int)
            msg = _("%(url)s returned with HTTP %(status)d") % msg_dict
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -487,8 +487,10 @@
             return faults.Fault(webob.exc.HTTPBadRequest(explanation=msg))
 
         project_id = args.pop("project_id", None)
-        if 'nova.context' in request.environ and project_id:
-            request.environ['nova.context'].project_id = project_id
+        if ('nova.context' in request.environ and project_id
+            and project_id != request.environ['nova.context'].project_id):
+            msg = _("Malformed request url")
+            return faults.Fault(webob.exc.HTTPBadRequest(explanation=msg))
 
         try:
             action_result = self.dispatch(request, action, args)
```
