# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3772_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3772_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 804-844 of the vulnerable file.

        Deletes the image and all its chunks from the Glance

        :param req: The WSGI/Webob Request object
        :param id: The opaque image identifier

        :raises HttpBadRequest if image registry is invalid
        :raises HttpNotFound if image or any chunk is not available
        :raises HttpUnauthorized if image or any chunk is not
                deleteable by the requesting user
        """
        self._enforce(req, 'delete_image')

        image = self.get_image_meta_or_404(req, id)
        if image['protected']:
            msg = _("Image is protected")
            LOG.debug(msg)
            raise HTTPForbidden(explanation=msg,
                                request=req,
                                content_type="text/plain")

        status = 'deleted'
        try:
            # The image's location field may be None in the case
            # of a saving or queued image, therefore don't ask a backend
            # to delete the image if the backend doesn't yet store it.
            # See https://bugs.launchpad.net/glance/+bug/747799
            if image['location']:
                if CONF.delayed_delete:
                    status = 'pending_delete'
                    schedule_delayed_delete_from_backend(image['location'], id)
                else:
                    safe_delete_from_backend(image['location'],
                                             req.context, id)

            registry.update_image_metadata(req.context, id, {'status': status})
            registry.delete_image_metadata(req.context, id)
        except exception.NotFound, e:
            msg = ("Failed to find image to delete: %(e)s" % locals())
            for line in msg.split('\n'):
                LOG.info(line)
            self.notifier.info('image.delete', msg)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -821,22 +821,28 @@
                                 request=req,
                                 content_type="text/plain")
 
-        status = 'deleted'
-        try:
+        if image['location'] and CONF.delayed_delete:
+            status = 'pending_delete'
+        else:
+            status = 'deleted'
+
+        try:
+            # Delete the image from the registry first, since we rely on it
+            # for authorization checks.
+            # See https://bugs.launchpad.net/glance/+bug/1065187
+            registry.update_image_metadata(req.context, id, {'status': status})
+            registry.delete_image_metadata(req.context, id)
+
             # The image's location field may be None in the case
             # of a saving or queued image, therefore don't ask a backend
             # to delete the image if the backend doesn't yet store it.
             # See https://bugs.launchpad.net/glance/+bug/747799
             if image['location']:
                 if CONF.delayed_delete:
-                    status = 'pending_delete'
                     schedule_delayed_delete_from_backend(image['location'], id)
                 else:
                     safe_delete_from_backend(image['location'],
                                              req.context, id)
-
-            registry.update_image_metadata(req.context, id, {'status': status})
-            registry.delete_image_metadata(req.context, id)
         except exception.NotFound, e:
             msg = ("Failed to find image to delete: %(e)s" % locals())
             for line in msg.split('\n'):
```
