# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 5538_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5538_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 372-412 of the vulnerable file.

            'root_gb': instance_type['root_gb'],
            'ephemeral_gb': instance_type['ephemeral_gb'],
            'display_name': display_name,
            'display_description': display_description,
            'user_data': user_data or '',
            'key_name': key_name,
            'key_data': key_data,
            'locked': False,
            'metadata': metadata,
            'access_ip_v4': access_ip_v4,
            'access_ip_v6': access_ip_v6,
            'availability_zone': availability_zone,
            'os_type': os_type,
            'architecture': architecture,
            'vm_mode': vm_mode,
            'root_device_name': root_device_name,
            'progress': 0,
            'auto_disk_config': auto_disk_config}

        LOG.debug(_("Going to run %s instances...") % num_instances)

        if create_instance_here:
            instance = self.create_db_entry_for_new_instance(
                    context, instance_type, image, base_options,
                    security_group, block_device_mapping)
            # Tells scheduler we created the instance already.
            base_options['uuid'] = instance['uuid']
            rpc_method = rpc.cast
        else:
            # We need to wait for the scheduler to create the instance
            # DB entries, because the instance *could* be # created in
            # a child zone.
            rpc_method = rpc.call

        # TODO(comstud): We should use rpc.multicall when we can
        # retrieve the full instance dictionary from the scheduler.
        # Otherwise, we could exceed the AMQP max message size limit.
        # This would require the schedulers' schedule_run_instances
        # methods to return an iterator vs a list.
        instances = self._schedule_run_instance(
                rpc_method,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -390,6 +390,22 @@
 
         LOG.debug(_("Going to run %s instances...") % num_instances)
 
+        # Validate the correct devices have been specified
+        for bdm in block_device_mapping:
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
+
         if create_instance_here:
             instance = self.create_db_entry_for_new_instance(
                     context, instance_type, image, base_options,
```
