# CrossVul Fix Pair: Improper Authentication in python
**Pair ID:** 3759_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3759_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```python
Lines 99-139 of the vulnerable file.


            { 'RegionOne':
                {'compute': {
                    'adminURL': u'http://host:8774/v1.1/tenantid',
                    'internalURL': u'http://host:8774/v1.1/tenant_id',
                    'name': 'Compute Service',
                    'publicURL': u'http://host:8774/v1.1/tenantid'},
                 'ec2': {
                    'adminURL': 'http://host:8773/services/Admin',
                    'internalURL': 'http://host:8773/services/Cloud',
                    'name': 'EC2 Service',
                    'publicURL': 'http://host:8773/services/Cloud'}}

        """
        raise exception.NotImplemented()


class ServiceController(wsgi.Application):
    def __init__(self):
        self.catalog_api = Manager()
        super(ServiceController, self).__init__()

    # CRUD extensions
    # NOTE(termie): this OS-KSADM stuff is not very consistent
    def get_services(self, context):
        service_list = self.catalog_api.list_services(context)
        service_refs = [self.catalog_api.get_service(context, x)
                        for x in service_list]
        return {'OS-KSADM:services': service_refs}

    def get_service(self, context, service_id):
        service_ref = self.catalog_api.get_service(context, service_id)
        if not service_ref:
            raise exception.ServiceNotFound(service_id=service_id)
        return {'OS-KSADM:service': service_ref}

    def delete_service(self, context, service_id):
        service_ref = self.catalog_api.get_service(context, service_id)
        if not service_ref:
            raise exception.ServiceNotFound(service_id=service_id)
        self.catalog_api.delete_service(context, service_id)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -116,29 +116,36 @@
 class ServiceController(wsgi.Application):
     def __init__(self):
         self.catalog_api = Manager()
+        self.identity_api = identity.Manager()
+        self.policy_api = policy.Manager()
+        self.token_api = token.Manager()
         super(ServiceController, self).__init__()
 
     # CRUD extensions
     # NOTE(termie): this OS-KSADM stuff is not very consistent
     def get_services(self, context):
+        self.assert_admin(context)
         service_list = self.catalog_api.list_services(context)
         service_refs = [self.catalog_api.get_service(context, x)
                         for x in service_list]
         return {'OS-KSADM:services': service_refs}
 
     def get_service(self, context, service_id):
+        self.assert_admin(context)
         service_ref = self.catalog_api.get_service(context, service_id)
         if not service_ref:
             raise exception.ServiceNotFound(service_id=service_id)
         return {'OS-KSADM:service': service_ref}
 
     def delete_service(self, context, service_id):
+        self.assert_admin(context)
         service_ref = self.catalog_api.get_service(context, service_id)
         if not service_ref:
             raise exception.ServiceNotFound(service_id=service_id)
         self.catalog_api.delete_service(context, service_id)
 
     def create_service(self, context, OS_KSADM_service):
+        self.assert_admin(context)
         service_id = uuid.uuid4().hex
         service_ref = OS_KSADM_service.copy()
         service_ref['id'] = service_id
```
