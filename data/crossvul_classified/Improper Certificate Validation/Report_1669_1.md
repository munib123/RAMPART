# CrossVul Fix Pair: Improper Certificate Validation in python
**Pair ID:** 1669_1
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1669_1`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```python
Lines 94-134 of the vulnerable file.

class ConsumerContentSchedulesAPI(PulpAPI):
    """
    Connection class to access consumer calls related to scheduled content install/uninstall/update
    Each function inside the class accepts an additional 'action' parameter. This is to specify a particular
    schedule action. Possible values are 'install', 'update' and 'uninstall'.
    """
    def __init__(self, pulp_connection):
        """
        @type:   pulp_connection: pulp.bindings.server.PulpConnection
        """
        super(ConsumerContentSchedulesAPI, self).__init__(pulp_connection)
        self.base_path = "/v2/consumers/%s/schedules/content/"

    def list_schedules(self, action, consumer_id):
        url = self.base_path % consumer_id + action + '/'
        return self.server.GET(url)

    def get_schedule(self, action, consumer_id, schedule_id):
        url = self.base_path % consumer_id + action + '/%s/' % schedule_id
        return self.server.GET(url)
    
    def add_schedule(self, action, consumer_id, schedule, units, failure_threshold=UNSPECIFIED,
                     enabled=UNSPECIFIED, options=UNSPECIFIED):
        url = self.base_path % consumer_id + action + '/'
        body = {
            'schedule' : schedule,
            'units': units,
            'failure_threshold' : failure_threshold,
            'enabled' : enabled,
            'options': options,
            }
        # Strip out anything that wasn't specified by the caller
        body = dict([(k, v) for k, v in body.items() if v is not UNSPECIFIED])
        return self.server.POST(url, body)
 
    def delete_schedule(self, action, consumer_id, schedule_id):
        url = self.base_path % consumer_id + action + '/%s/' % schedule_id
        return self.server.DELETE(url)

    def update_schedule(self, action, consumer_id, schedule_id, schedule=UNSPECIFIED, units=UNSPECIFIED,
                        failure_threshold=UNSPECIFIED, remaining_runs=UNSPECIFIED, enabled=UNSPECIFIED,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -111,7 +111,7 @@
     def get_schedule(self, action, consumer_id, schedule_id):
         url = self.base_path % consumer_id + action + '/%s/' % schedule_id
         return self.server.GET(url)
-    
+
     def add_schedule(self, action, consumer_id, schedule, units, failure_threshold=UNSPECIFIED,
                      enabled=UNSPECIFIED, options=UNSPECIFIED):
         url = self.base_path % consumer_id + action + '/'
@@ -125,7 +125,7 @@
         # Strip out anything that wasn't specified by the caller
         body = dict([(k, v) for k, v in body.items() if v is not UNSPECIFIED])
         return self.server.POST(url, body)
- 
+
     def delete_schedule(self, action, consumer_id, schedule_id):
         url = self.base_path % consumer_id + action + '/%s/' % schedule_id
         return self.server.DELETE(url)
@@ -156,7 +156,7 @@
         if repo_id:
             path += '%s/' % repo_id
         return self.server.GET(path)
-    
+
     def bind(self, consumer_id, repo_id, distributor_id, notify_agent=True, binding_config=None):
         path = self.BASE_PATH % consumer_id
         data = {
@@ -166,7 +166,7 @@
             'binding_config': binding_config or {}
         }
         return self.server.POST(path, data)
-    
+
     def unbind(self, consumer_id, repo_id, distributor_id, force=False):
         path = self.BASE_PATH % consumer_id + "%s/" % repo_id + "%s/" % distributor_id
         body = dict(force=force)
```
