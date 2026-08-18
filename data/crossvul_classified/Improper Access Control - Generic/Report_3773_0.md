# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3773_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3773_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 710-750 of the vulnerable file.

    def delete(self, req, id):
        """
        Deletes the image and all its chunks from the Glance

        :param req: The WSGI/Webob Request object
        :param id: The opaque image identifier

        :raises HttpBadRequest if image registry is invalid
        :raises HttpNotFound if image or any chunk is not available
        :raises HttpUnauthorized if image or any chunk is not
                deleteable by the requesting user
        """
        self._enforce(req, 'delete_image')
        if req.context.read_only:
            msg = _("Read-only access")
            logger.debug(msg)
            raise HTTPForbidden(msg, request=req,
                                content_type="text/plain")

        image = self.get_image_meta_or_404(req, id)
        if image['protected']:
            msg = _("Image is protected")
            logger.debug(msg)
            raise HTTPForbidden(msg, request=req,
                                content_type="text/plain")

        # The image's location field may be None in the case
        # of a saving or queued image, therefore don't ask a backend
        # to delete the image if the backend doesn't yet store it.
        # See https://bugs.launchpad.net/glance/+bug/747799
        try:
            if image['location']:
                schedule_delete_from_backend(image['location'], self.conf,
                                             req.context, id)
            registry.delete_image_metadata(req.context, id)
        except exception.NotFound, e:
            msg = ("Failed to find image to delete: %(e)s" % locals())
            for line in msg.split('\n'):
                logger.info(line)
            self.notifier.info('image.delete', msg)
            raise HTTPNotFound(msg, request=req, content_type="text/plain")
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -727,6 +727,15 @@
                                 content_type="text/plain")
 
         image = self.get_image_meta_or_404(req, id)
+
+        if not (req.context.is_admin
+                or image['owner'] == None
+                or image['owner'] == req.context.owner):
+            msg = _("Unable to delete image you do not own")
+            logger.debug(msg)
+            raise HTTPForbidden(msg, request=req,
+                                content_type="text/plain")
+
         if image['protected']:
             msg = _("Image is protected")
             logger.debug(msg)
```
