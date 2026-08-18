# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3784_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3784_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 243-291 of the vulnerable file.

        updates[key] = change['value']

    def _do_remove_property(self, updates, change):
        """ Remove an image property, ensuring it's present. """
        key = change['path'][1]
        if key not in updates:
            msg = _("Property %s does not exist.")
            raise webob.exc.HTTPConflict(msg % key)
        del updates[key]

    @utils.mutating
    def delete(self, req, image_id):
        self._enforce(req, 'delete_image')
        image = self._get_image(req.context, image_id)

        if image['protected']:
            msg = _("Unable to delete as image %(image_id)s is protected"
                    % locals())
            raise webob.exc.HTTPForbidden(explanation=msg)

        status = 'deleted'
        if image['location']:
            if CONF.delayed_delete:
                status = 'pending_delete'
                self.store_api.schedule_delayed_delete_from_backend(
                                image['location'], id)
            else:
                self.store_api.safe_delete_from_backend(image['location'],
                                                        req.context, id)

        try:
            self.db_api.image_update(req.context, image_id, {'status': status})
            self.db_api.image_destroy(req.context, image_id)
        except (exception.NotFound, exception.Forbidden):
            msg = ("Failed to find image %(image_id)s to delete" % locals())
            LOG.info(msg)
            raise webob.exc.HTTPNotFound()
        else:
            self.notifier.info('image.delete', image)


class RequestDeserializer(wsgi.JSONRequestDeserializer):

    _readonly_properties = ['created_at', 'updated_at', 'status', 'checksum',
                            'size', 'direct_url', 'self', 'file', 'schema']
    _reserved_properties = ['owner', 'is_public', 'location', 'deleted',
                            'deleted_at']
    _base_properties = ['checksum', 'created_at', 'container_format',
                        'disk_format', 'id', 'min_disk', 'min_ram', 'name',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -260,19 +260,22 @@
                     % locals())
             raise webob.exc.HTTPForbidden(explanation=msg)
 
-        status = 'deleted'
-        if image['location']:
-            if CONF.delayed_delete:
-                status = 'pending_delete'
-                self.store_api.schedule_delayed_delete_from_backend(
-                                image['location'], id)
-            else:
-                self.store_api.safe_delete_from_backend(image['location'],
-                                                        req.context, id)
+        if image['location'] and CONF.delayed_delete:
+            status = 'pending_delete'
+        else:
+            status = 'deleted'
 
         try:
             self.db_api.image_update(req.context, image_id, {'status': status})
             self.db_api.image_destroy(req.context, image_id)
+
+            if image['location']:
+                if CONF.delayed_delete:
+                    self.store_api.schedule_delayed_delete_from_backend(
+                                    image['location'], id)
+                else:
+                    self.store_api.safe_delete_from_backend(image['location'],
+                                                            req.context, id)
         except (exception.NotFound, exception.Forbidden):
             msg = ("Failed to find image %(image_id)s to delete" % locals())
             LOG.info(msg)
```
