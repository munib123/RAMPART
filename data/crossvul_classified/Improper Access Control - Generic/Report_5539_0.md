# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 5539_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5539_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 490-530 of the vulnerable file.

                    raise exception.InstanceUserDataMalformed()

            options_from_image = self._inherit_properties_from_image(
                    image, auto_disk_config)

            base_options.update(options_from_image)

            LOG.debug(_("Going to run %s instances...") % num_instances)

            filter_properties = dict(scheduler_hints=scheduler_hints)
            if context.is_admin and forced_host:
                filter_properties['force_hosts'] = [forced_host]

            for i in xrange(num_instances):
                options = base_options.copy()
                instance = self.create_db_entry_for_new_instance(
                        context, instance_type, image, options,
                        security_group, block_device_mapping)
                instances.append(instance)
                instance_uuids.append(instance['uuid'])

        # In the case of any exceptions, attempt DB cleanup and rollback the
        # quota reservations.
        except Exception:
            with excutils.save_and_reraise_exception():
                try:
                    for instance_uuid in instance_uuids:
                        self.db.instance_destroy(context, instance_uuid)
                finally:
                    QUOTAS.rollback(context, quota_reservations)

        # Commit the reservations
        QUOTAS.commit(context, quota_reservations)

        request_spec = {
            'image': jsonutils.to_primitive(image),
            'instance_properties': base_options,
            'instance_type': instance_type,
            'instance_uuids': instance_uuids,
            'block_device_mapping': block_device_mapping,
            'security_group': security_group,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -507,6 +507,11 @@
                         security_group, block_device_mapping)
                 instances.append(instance)
                 instance_uuids.append(instance['uuid'])
+                self._validate_bdm(context, instance)
+                # send a state update notification for the initial create to
+                # show it going from non-existent to BUILDING
+                notifications.send_update_with_states(context, instance, None,
+                        vm_states.BUILDING, None, None, service="api")
 
         # In the case of any exceptions, attempt DB cleanup and rollback the
         # quota reservations.
@@ -622,6 +627,23 @@
 
             self.db.block_device_mapping_update_or_create(elevated_context,
                                                           values)
+
+    def _validate_bdm(self, context, instance):
+        for bdm in self.db.block_device_mapping_get_all_by_instance(
+                context, instance['uuid']):
+            # NOTE(vish): For now, just make sure the volumes are accessible.
+            snapshot_id = bdm.get('snapshot_id')
+            volume_id = bdm.get('volume_id')
+            if volume_id is not None:
+                try:
+                    self.volume_api.get(context, volume_id)
+                except Exception:
+                    raise exception.InvalidBDMVolume(id=volume_id)
+            elif snapshot_id is not None:
+                try:
+                    self.volume_api.get_snapshot(context, snapshot_id)
+                except Exception:
+                    raise exception.InvalidBDMSnapshot(id=snapshot_id)
 
     def _populate_instance_for_bdm(self, context, instance, instance_type,
             image, block_device_mapping):
@@ -734,11 +756,6 @@
 
         self._populate_instance_for_bdm(context, instance,
                 instance_type, image, block_device_mapping)
-
-        # send a state update notification for the initial create to
-        # show it going from non-existent to BUILDING
-        notifications.send_update_with_states(context, instance, None,
-                vm_states.BUILDING, None, None, service="api")
 
         return instance
 
```
