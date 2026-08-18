# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3633_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3633_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 23-63 of the vulnerable file.

from nova.api.openstack import extensions


class QuotaSetsController(object):

    def _format_quota_set(self, project_id, quota_set):
        """Convert the quota object to a result dict"""

        return {'quota_set': {
            'id': str(project_id),
            'metadata_items': quota_set['metadata_items'],
            'injected_file_content_bytes':
             quota_set['injected_file_content_bytes'],
            'volumes': quota_set['volumes'],
            'gigabytes': quota_set['gigabytes'],
            'ram': quota_set['ram'],
            'floating_ips': quota_set['floating_ips'],
            'instances': quota_set['instances'],
            'injected_files': quota_set['injected_files'],
            'cores': quota_set['cores'],
        }}

    def show(self, req, id):
        context = req.environ['nova.context']
        try:
            db.sqlalchemy.api.authorize_project_context(context, id)
            return self._format_quota_set(id,
                                        quota.get_project_quotas(context, id))
        except exception.NotAuthorized:
            return webob.Response(status_int=403)

    def update(self, req, id, body):
        context = req.environ['nova.context']
        project_id = id
        resources = ['metadata_items', 'injected_file_content_bytes',
                'volumes', 'gigabytes', 'ram', 'floating_ips', 'instances',
                'injected_files', 'cores']
        for key in body['quota_set'].keys():
            if key in resources:
                value = int(body['quota_set'][key])
                try:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,6 +40,8 @@
             'instances': quota_set['instances'],
             'injected_files': quota_set['injected_files'],
             'cores': quota_set['cores'],
+            'security_groups': quota_set['security_groups'],
+            'security_group_rules': quota_set['security_group_rules'],
         }}
 
     def show(self, req, id):
@@ -56,7 +58,8 @@
         project_id = id
         resources = ['metadata_items', 'injected_file_content_bytes',
                 'volumes', 'gigabytes', 'ram', 'floating_ips', 'instances',
-                'injected_files', 'cores']
+                'injected_files', 'cores', 'security_groups',
+                'security_group_rules']
         for key in body['quota_set'].keys():
             if key in resources:
                 value = int(body['quota_set'][key])
```
