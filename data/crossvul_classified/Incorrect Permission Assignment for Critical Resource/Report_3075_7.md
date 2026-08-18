# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in java
**Pair ID:** 3075_7
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3075_7`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```java
Lines 2465-2505 of the vulnerable file.

    @Test
    public void factorySynchronization() throws Throwable {

        setUp(this.nodeCount);
        this.host.joinNodesAndVerifyConvergence(this.nodeCount);

        factorySynchronizationNoChildren();

        factoryDuplicatePost();
    }

    @Test
    public void replicationWithAuthzCacheClear() throws Throwable {
        this.isAuthorizationEnabled = true;
        setUp(this.nodeCount);
        this.host.joinNodesAndVerifyConvergence(this.nodeCount);
        this.host.setNodeGroupQuorum(this.nodeCount);

        VerificationHost groupHost = this.host.getPeerHost();

        // wait for auth related services to be stabilized
        groupHost.waitForReplicatedFactoryServiceAvailable(
                UriUtils.buildUri(groupHost, UserService.FACTORY_LINK));
        groupHost.waitForReplicatedFactoryServiceAvailable(
                UriUtils.buildUri(groupHost, UserGroupService.FACTORY_LINK));
        groupHost.waitForReplicatedFactoryServiceAvailable(
                UriUtils.buildUri(groupHost, ResourceGroupService.FACTORY_LINK));
        groupHost.waitForReplicatedFactoryServiceAvailable(
                UriUtils.buildUri(groupHost, RoleService.FACTORY_LINK));

        String fooUserLink = UriUtils.buildUriPath(ServiceUriPaths.CORE_AUTHZ_USERS,
                "foo@vmware.com");
        String barUserLink = UriUtils.buildUriPath(ServiceUriPaths.CORE_AUTHZ_USERS,
                "bar@vmware.com");
        String bazUserLink = UriUtils.buildUriPath(ServiceUriPaths.CORE_AUTHZ_USERS,
                "baz@vmware.com");

        groupHost.setSystemAuthorizationContext();

        // create user, user-group, resource-group, role for foo@vmware.com
        //   user: /core/authz/users/foo@vmware.com
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2482,6 +2482,7 @@
 
         VerificationHost groupHost = this.host.getPeerHost();
 
+        groupHost.setSystemAuthorizationContext();
         // wait for auth related services to be stabilized
         groupHost.waitForReplicatedFactoryServiceAvailable(
                 UriUtils.buildUri(groupHost, UserService.FACTORY_LINK));
@@ -2499,7 +2500,7 @@
         String bazUserLink = UriUtils.buildUriPath(ServiceUriPaths.CORE_AUTHZ_USERS,
                 "baz@vmware.com");
 
-        groupHost.setSystemAuthorizationContext();
+
 
         // create user, user-group, resource-group, role for foo@vmware.com
         //   user: /core/authz/users/foo@vmware.com
@@ -2709,7 +2710,7 @@
 
             // based on the role created in test, all users have access to ExampleService
             this.host.sendAndWaitExpectSuccess(
-                    Operation.createGet(UriUtils.buildStatsUri(peer, ExampleService.FACTORY_LINK)));
+                    Operation.createGet(UriUtils.buildUri(peer, ExampleService.FACTORY_LINK)));
         }
 
         this.host.waitFor("Timeout waiting for correct auth cache state",
```
