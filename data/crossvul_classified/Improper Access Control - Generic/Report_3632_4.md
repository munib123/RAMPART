# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3632_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3632_4`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 37-77 of the vulnerable file.

               default=10,
               help='number of volumes allowed per project'),
    cfg.IntOpt('quota_gigabytes',
               default=1000,
               help='number of volume gigabytes allowed per project'),
    cfg.IntOpt('quota_floating_ips',
               default=10,
               help='number of floating ips allowed per project'),
    cfg.IntOpt('quota_metadata_items',
               default=128,
               help='number of metadata items allowed per instance'),
    cfg.IntOpt('quota_injected_files',
               default=5,
               help='number of injected files allowed'),
    cfg.IntOpt('quota_injected_file_content_bytes',
               default=10 * 1024,
               help='number of bytes allowed per injected file'),
    cfg.IntOpt('quota_injected_file_path_bytes',
               default=255,
               help='number of bytes allowed per injected file path'),
    ]

FLAGS = flags.FLAGS
FLAGS.register_opts(quota_opts)


quota_resources = ['metadata_items', 'injected_file_content_bytes',
        'volumes', 'gigabytes', 'ram', 'floating_ips', 'instances',
        'injected_files', 'cores']


def _get_default_quotas():
    defaults = {
        'instances': FLAGS.quota_instances,
        'cores': FLAGS.quota_cores,
        'ram': FLAGS.quota_ram,
        'volumes': FLAGS.quota_volumes,
        'gigabytes': FLAGS.quota_gigabytes,
        'floating_ips': FLAGS.quota_floating_ips,
        'metadata_items': FLAGS.quota_metadata_items,
        'injected_files': FLAGS.quota_injected_files,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -54,6 +54,12 @@
     cfg.IntOpt('quota_injected_file_path_bytes',
                default=255,
                help='number of bytes allowed per injected file path'),
+    cfg.IntOpt('quota_security_groups',
+               default=10,
+               help='number of security groups per project'),
+    cfg.IntOpt('quota_security_group_rules',
+               default=20,
+               help='number of security rules per security group'),
     ]
 
 FLAGS = flags.FLAGS
@@ -62,7 +68,7 @@
 
 quota_resources = ['metadata_items', 'injected_file_content_bytes',
         'volumes', 'gigabytes', 'ram', 'floating_ips', 'instances',
-        'injected_files', 'cores']
+        'injected_files', 'cores', 'security_groups', 'security_group_rules']
 
 
 def _get_default_quotas():
@@ -77,6 +83,8 @@
         'injected_files': FLAGS.quota_injected_files,
         'injected_file_content_bytes':
             FLAGS.quota_injected_file_content_bytes,
+        'security_groups': FLAGS.quota_security_groups,
+        'security_group_rules': FLAGS.quota_security_group_rules,
     }
     # -1 in the quota flags means unlimited
     return defaults
@@ -170,6 +178,32 @@
     return min(requested_floating_ips, allowed_floating_ips)
 
 
+def allowed_security_groups(context, requested_security_groups):
+    """Check quota and return min(requested, allowed) security groups."""
+    project_id = context.project_id
+    context = context.elevated()
+    used_sec_groups = db.security_group_count_by_project(context, project_id)
+    quota = get_project_quotas(context, project_id)
+    allowed_sec_groups = _get_request_allotment(requested_security_groups,
+                                                  used_sec_groups,
+                                                  quota['security_groups'])
+    return min(requested_security_groups, allowed_sec_groups)
+
+
+def allowed_security_group_rules(context, security_group_id,
+        requested_rules):
+    """Check quota and return min(requested, allowed) sec group rules."""
+    project_id = context.project_id
+    context = context.elevated()
+    used_rules = db.security_group_rule_count_by_group(context,
+                                                            security_group_id)
+    quota = get_project_quotas(context, project_id)
+    allowed_rules = _get_request_allotment(requested_rules,
+                                              used_rules,
+                                              quota['security_group_rules'])
+    return min(requested_rules, allowed_rules)
+
+
 def _calculate_simple_quota(context, resource, requested):
     """Check quota for resource; return min(requested, allowed)."""
     quota = get_project_quotas(context, context.project_id)
```
